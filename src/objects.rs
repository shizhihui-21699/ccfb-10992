//! Raw commit/tag parsing.
//!
//! Git verifies signatures over the commit or tag buffer with the signature
//! header removed (and, for `gpgsig`, continuation lines unindented). That is
//! exactly what `parse_buffer_signed_by_header` does in `commit.c`. We
//! therefore parse the raw object bytes ourselves instead of going through a
//! structured commit parser, so the payload handed to a verifier is
//! byte-identical to what `git verify-commit` would pass to `gpg` /
//! `ssh-keygen`.

/// The signature headers Git knows about, indexed by object hash algorithm
/// (`gpg_sig_headers[]` in `commit.c`): SHA-1 uses `gpgsig`, SHA-256 uses
/// `gpgsig-sha256`.
const GPG_SIG_HEADERS: [&str; 3] = ["", "gpgsig", "gpgsig-sha256"];

/// A parsed signed object (commit or annotated tag).
#[derive(Debug, Clone)]
pub struct SignedObject {
    /// Signature text with the `gpgsig` header indentation removed, i.e. the
    /// exact byte string that Git writes to a temp file and passes to
    /// `ssh-keygen -Y verify` / `gpg --verify`.
    pub signature: Vec<u8>,
    /// The object bytes with the signature header removed. This is the text
    /// that gets hashed/signed.
    pub payload: Vec<u8>,
    /// How the signature was embedded.
    pub header: SignatureHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureHeader {
    /// `gpgsig` / `gpgsig-sha256` header in a commit object.
    GpgSig,
    /// An annotated tag with the signature after the message body.
    Inline,
}

/// Split a commit's raw bytes into its signature and payload.
///
/// Mirrors `parse_buffer_signed_by_header` in `commit.c`. Returns `None` when
/// the object carries no signature under `header`. Lines belonging to the
/// *other* signature header (`gpgsig` vs `gpgsig-sha256`) are stripped from the
/// payload but not collected, which is what Git does too.
pub fn parse_signed_commit(buffer: &[u8], hash_algo_index: usize) -> Option<SignedObject> {
    let header = GPG_SIG_HEADERS.get(hash_algo_index)?;
    if header.is_empty() {
        return None;
    }

    let mut payload = Vec::with_capacity(buffer.len());
    let mut signature = Vec::new();
    let mut in_signature = false;
    let mut saw_signature = false;
    let mut other_signature = false;

    let mut offset = 0usize;
    while offset < buffer.len() {
        let line_end = match buffer[offset..].iter().position(|b| *b == b'\n') {
            Some(i) => offset + i + 1,
            None => buffer.len(),
        };
        let mut line = &buffer[offset..line_end];
        let mut next = line_end;

        let mut sig_chunk: Option<&[u8]> = None;
        if in_signature && line.first() == Some(&b' ') {
            sig_chunk = Some(&line[1..]);
        } else if let Some(rest) = line.strip_prefix(header.as_bytes()) {
            if rest.first() == Some(&b' ') {
                sig_chunk = Some(&rest[1..]);
                other_signature = false;
            } else {
                // `gpgsig` with no value: an empty signature, not ours.
            }
        } else if line.starts_with(b"gpgsig") {
            other_signature = true;
        } else if other_signature && line.first() != Some(&b' ') {
            other_signature = false;
        }

        if let Some(chunk) = sig_chunk {
            signature.extend_from_slice(chunk);
            saw_signature = true;
            in_signature = true;
        } else {
            if line.first() == Some(&b'\n') {
                // Blank line: dump the whole remainder of the buffer.
                next = buffer.len();
                line = &buffer[offset..next];
            }
            if !other_signature {
                payload.extend_from_slice(line);
            }
            in_signature = false;
        }
        offset = next;
    }

    saw_signature.then_some(SignedObject {
        signature,
        payload,
        header: SignatureHeader::GpgSig,
    })
}

/// Parse an annotated tag.
///
/// Tags carry the signature after the message body. Git's `parse_signature`
/// finds the first signature block and treats everything before it as payload,
/// then runs `remove_signature` over that prefix. We mirror the two shapes
/// Git produces: an inline `-----BEGIN … SIGNATURE-----` block appended to the
/// message, or a `gpgsig`-style header (after `git tag -s` rewrites).
pub fn parse_signed_tag(buffer: &[u8]) -> Option<SignedObject> {
    let mut sig_start = None;
    let mut offset = 0usize;
    while offset < buffer.len() {
        let line_end = match buffer[offset..].iter().position(|b| *b == b'\n') {
            Some(i) => offset + i + 1,
            None => buffer.len(),
        };
        let line = &buffer[offset..line_end];
        if line.starts_with(b"-----BEGIN PGP SIGNATURE-----")
            || line.starts_with(b"-----BEGIN SSH SIGNATURE-----")
            || line.starts_with(b"-----BEGIN PGP MESSAGE-----")
        {
            sig_start = Some(offset);
            break;
        }
        offset = line_end;
    }

    if let Some(start) = sig_start {
        return Some(SignedObject {
            signature: buffer[start..].to_vec(),
            payload: buffer[..start].to_vec(),
            header: SignatureHeader::Inline,
        });
    }

    // A tag may have been rewritten to carry a gpgsig header instead.
    parse_signed_commit(buffer, 1).map(|mut s| {
        s.header = SignatureHeader::Inline;
        s
    })
}

/// The commit's committer timestamp, in Unix seconds.
///
/// Git parses this out of the `committer` ident line and uses it as
/// `payload_timestamp`, i.e. the "verify time" handed to `gpg -O verify-time`
/// and `ssh-keygen -O verify-time`. Reading it from the raw object keeps the
/// auditor independent of any commit-parsing library.
pub fn committer_timestamp(buffer: &[u8]) -> Option<i64> {
    ident_timestamp(buffer, b"committer ")
}

/// The tagger timestamp, for annotated tags.
pub fn tagger_timestamp(buffer: &[u8]) -> Option<i64> {
    ident_timestamp(buffer, b"tagger ")
}

fn ident_timestamp(buffer: &[u8], header: &[u8]) -> Option<i64> {
    // Only the header block is relevant; stop at the blank line separating it
    // from the message so a line of the message can never be mistaken for an
    // ident.
    for line in buffer.split_inclusive(|b| *b == b'\n') {
        if line == b"\n" {
            break;
        }
        let Some(rest) = line.strip_prefix(header) else {
            continue;
        };
        // "<name> <email> <unix-seconds> <tz>"
        let text = std::str::from_utf8(rest).ok()?;
        let mut parts = text.split_ascii_whitespace().rev();
        let _tz = parts.next()?;
        return parts.next()?.parse().ok();
    }
    None
}

/// The commit's tree id (hex), used for reporting.
pub fn header_value(buffer: &[u8], header: &[u8]) -> Option<String> {
    for line in buffer.split_inclusive(|b| *b == b'\n') {
        if let Some(rest) = line.strip_prefix(header) {
            let value = String::from_utf8_lossy(rest).trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Extract the first `mergetag` header value with continuation lines
/// unindented, exactly like `read_commit_extra_header_lines`.
pub fn mergetag_payload(raw: &[u8]) -> Option<Vec<u8>> {
    let mut collecting = false;
    let mut out = Vec::new();
    for line in raw.split_inclusive(|b| *b == b'\n') {
        if line == b"\n" {
            break;
        }
        if collecting {
            if let Some(rest) = line.strip_prefix(b" ") {
                out.extend_from_slice(rest);
                continue;
            }
            return if out.is_empty() { None } else { Some(out) };
        }
        if let Some(rest) = line.strip_prefix(b"mergetag ") {
            collecting = true;
            out.extend_from_slice(rest);
        }
    }
    if collecting && !out.is_empty() {
        Some(out)
    } else {
        None
    }
}
