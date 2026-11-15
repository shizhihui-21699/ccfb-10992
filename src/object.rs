//! Reading git objects (commits and tags) straight out of the object database
//! and splitting them into the exact payload/signature pair that git hands to
//! its verifier.
//!
//! For commits this mirrors `parse_buffer_signed_by_header()` in git's
//! `commit.c`: the `gpgsig` header and its continuation lines are removed from
//! the payload, and *all* `gpgsig*` headers are kept out of the signed payload.
//! For tags this mirrors `parse_signature()` in git's `gpg-interface.c`: the
//! payload is everything before the signature armor line, with any embedded
//! `gpgsig` headers stripped by `remove_signature()`.

use std::fmt;

/// Signature envelope formats git knows about (`get_format_by_sig`).
pub const SSH_SIGNATURE_BEGIN: &[u8] = b"-----BEGIN SSH SIGNATURE-----";
pub const PGP_SIGNATURE_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
pub const PGP_MESSAGE_BEGIN: &[u8] = b"-----BEGIN PGP MESSAGE-----";
pub const X509_SIGNED_MESSAGE_BEGIN: &[u8] = b"-----BEGIN SIGNED MESSAGE-----";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    pub fn from_oid_len(len: usize) -> HashAlgorithm {
        if len == 32 {
            HashAlgorithm::Sha256
        } else {
            HashAlgorithm::Sha1
        }
    }

    fn primary_sig_header(self) -> &'static [u8] {
        match self {
            HashAlgorithm::Sha1 => b"gpgsig",
            HashAlgorithm::Sha256 => b"gpgsig-sha256",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
        }
    }
}

/// The signing format implied by a signature envelope's first line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFormat {
    OpenPgp,
    Ssh,
    X509,
    Unknown,
}

impl SignatureFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureFormat::OpenPgp => "openpgp",
            SignatureFormat::Ssh => "ssh",
            SignatureFormat::X509 => "x509",
            SignatureFormat::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SignatureFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Mirrors git's `get_format_by_sig()`: only the start of the buffer is looked
/// at, and the first known armor marker wins.
pub fn detect_format(signature: &[u8]) -> SignatureFormat {
    if signature.starts_with(PGP_SIGNATURE_BEGIN) || signature.starts_with(PGP_MESSAGE_BEGIN) {
        SignatureFormat::OpenPgp
    } else if signature.starts_with(SSH_SIGNATURE_BEGIN) {
        SignatureFormat::Ssh
    } else if signature.starts_with(X509_SIGNED_MESSAGE_BEGIN) {
        SignatureFormat::X509
    } else {
        SignatureFormat::Unknown
    }
}

/// A commit object split into what git signs and the signature itself.
#[derive(Debug, Clone)]
pub struct ParsedCommit {
    pub oid: String,
    pub tree: String,
    pub parents: Vec<String>,
    pub author: Option<String>,
    pub committer: Option<String>,
    /// Payload that the signature covers (commit buffer minus `gpgsig`).
    pub payload: Vec<u8>,
    /// Raw signature block, or `None` when the commit is unsigned.
    pub signature: Option<Vec<u8>>,
    pub format: SignatureFormat,
}

impl ParsedCommit {
    pub fn is_merge(&self) -> bool {
        self.parents.len() > 1
    }

    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

/// Split a raw commit buffer exactly like git's
/// `parse_buffer_signed_by_header()`.
pub fn split_commit(buf: &[u8], algo: HashAlgorithm) -> (Vec<u8>, Option<Vec<u8>>) {
    let primary = algo.primary_sig_header();
    let mut payload = Vec::with_capacity(buf.len());
    let mut signature: Option<Vec<u8>> = None;
    let mut in_signature = false;
    let mut other_signature = false;
    let mut pos = 0usize;

    while pos < buf.len() {
        let next = match memchr::memchr(b'\n', &buf[pos..]) {
            Some(i) => pos + i + 1,
            None => buf.len(),
        };
        let line = &buf[pos..next];
        let is_continuation = line.first() == Some(&b' ');
        let mut is_signature_line = false;

        if in_signature && is_continuation {
            if let Some(sig) = signature.as_mut() {
                sig.extend_from_slice(&line[1..]);
            }
            is_signature_line = true;
        } else if line.starts_with(primary) && line.get(primary.len()) == Some(&b' ') {
            let sig = signature.get_or_insert_with(|| Vec::with_capacity(1024));
            sig.extend_from_slice(&line[primary.len() + 1..]);
            other_signature = false;
            is_signature_line = true;
        } else if line.starts_with(b"gpgsig") {
            // A signature header for another hash algorithm (e.g. gpgsig-sha256
            // in a sha1 repository). Its value must not enter the payload.
            other_signature = true;
        } else if other_signature && !is_continuation {
            other_signature = false;
        }

        if is_signature_line {
            in_signature = true;
        } else {
            if line.first() == Some(&b'\n') {
                // Git dumps the whole remainder of the buffer in one go.
                if !other_signature {
                    payload.extend_from_slice(&buf[pos..]);
                }
                break;
            }
            if !other_signature {
                payload.extend_from_slice(line);
            }
            in_signature = false;
        }

        pos = next;
    }

    (payload, signature)
}

/// A tag object split into what git signs and the signature itself.
#[derive(Debug, Clone)]
pub struct ParsedTag {
    pub oid: String,
    pub target: Option<String>,
    pub target_type: Option<String>,
    pub tag_name: Option<String>,
    pub tagger: Option<String>,
    pub payload: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub format: SignatureFormat,
}

/// Split a raw tag buffer like git's `parse_signature()`.
pub fn split_tag(buf: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    let match_at = signature_offset(buf);
    if match_at != buf.len() {
        let mut payload = buf[..match_at].to_vec();
        remove_signature(&mut payload);
        (payload, Some(buf[match_at..].to_vec()))
    } else {
        (buf.to_vec(), None)
    }
}

/// Mirrors `parse_signed_buffer()`: the offset of the *last* line that starts
/// with a known armor marker, or `buf.len()` when there is none.
fn signature_offset(buf: &[u8]) -> usize {
    let mut pos = 0usize;
    let mut found = buf.len();
    while pos < buf.len() {
        if detect_format(&buf[pos..]) != SignatureFormat::Unknown {
            found = pos;
        }
        pos = match memchr::memchr(b'\n', &buf[pos..]) {
            Some(i) => pos + i + 1,
            None => buf.len(),
        };
    }
    found
}

/// Mirrors `remove_signature()` from git's commit.c, including its use of a
/// fixed two-slot array and its cursor semantics.
///
/// Transliterated rather than generalised on purpose: git's behaviour when a
/// `gpgsig` line appears without a recognised header name (the `in_signature`
/// flag is left untouched) and its "later block overwrites the current slot"
/// behaviour are quirks that a tidier implementation would not reproduce, and
/// this function exists only to agree with git on tag payloads.
fn remove_signature(buf: &mut Vec<u8>) {
    /// Offsets of a removable block. git stores raw pointers; byte offsets into
    /// the still-unmodified buffer are equivalent because removal happens after
    /// the scan.
    type Slot = Option<(usize, usize)>;

    let mut sigs: [Slot; 2] = [None, None];
    let mut sigp = 0usize;
    let mut in_signature = false;
    let mut line = 0usize;

    while line < buf.len() {
        let mut next = match memchr::memchr(b'\n', &buf[line..]) {
            Some(i) => line + i + 1,
            None => buf.len(),
        };
        let is_continuation = buf[line] == b' ';
        let starts_gpgsig = buf[line..].starts_with(b"gpgsig");

        if in_signature && is_continuation {
            if let Some(Some(entry)) = sigs.get_mut(sigp) {
                entry.1 = next;
            }
        } else if starts_gpgsig {
            // Only `gpgsig ` and `gpgsig-sha256 ` are recognised; anything else
            // beginning with "gpgsig" changes nothing (not even in_signature).
            for header in [b"gpgsig".as_slice(), b"gpgsig-sha256".as_slice()] {
                if buf[line..].starts_with(header) && buf.get(line + header.len()) == Some(&b' ') {
                    if let Some(slot) = sigs.get_mut(sigp) {
                        *slot = Some((line, next));
                    }
                    in_signature = true;
                }
            }
        } else {
            if buf[line] == b'\n' {
                // git dumps the whole remainder of the buffer here, which ends
                // the scan: any later `gpgsig` header stays in the payload.
                next = buf.len();
            }
            if in_signature && sigp < sigs.len() {
                sigp += 1;
            }
            in_signature = false;
        }
        line = next;
    }

    // Remove the later block first so the earlier offsets stay valid.
    for slot in sigs.iter().rev().flatten() {
        buf.drain(slot.0..slot.1);
    }
}

/// Parse commit headers without interpreting the signature.
pub fn parse_commit(buf: &[u8], oid: String, algo: HashAlgorithm) -> ParsedCommit {
    let (payload, signature) = split_commit(buf, algo);
    let mut tree = String::new();
    let mut parents = Vec::new();
    let mut author = None;
    let mut committer = None;

    let mut pos = 0usize;
    while pos < buf.len() {
        let next = match memchr::memchr(b'\n', &buf[pos..]) {
            Some(i) => pos + i + 1,
            None => buf.len(),
        };
        let line = &buf[pos..next];
        if line.first() == Some(&b'\n') || line.first() == Some(&b' ') {
            break;
        }
        if let Some(value) = header_value(line, b"tree ") {
            tree = value.to_string();
        } else if let Some(value) = header_value(line, b"parent ") {
            parents.push(value.to_string());
        } else if let Some(value) = header_value(line, b"author ") {
            author = Some(value.to_string());
        } else if let Some(value) = header_value(line, b"committer ") {
            committer = Some(value.to_string());
        }
        pos = next;
    }

    let format = signature
        .as_deref()
        .map(detect_format)
        .unwrap_or(SignatureFormat::Unknown);

    ParsedCommit {
        oid,
        tree,
        parents,
        author,
        committer,
        payload,
        signature,
        format,
    }
}

/// Parse tag headers without interpreting the signature.
pub fn parse_tag(buf: &[u8], oid: String) -> ParsedTag {
    let (payload, signature) = split_tag(buf);
    let mut target = None;
    let mut target_type = None;
    let mut tag_name = None;
    let mut tagger = None;

    let mut pos = 0usize;
    while pos < buf.len() {
        let next = match memchr::memchr(b'\n', &buf[pos..]) {
            Some(i) => pos + i + 1,
            None => buf.len(),
        };
        let line = &buf[pos..next];
        if line.first() == Some(&b'\n') || line.first() == Some(&b' ') {
            break;
        }
        if let Some(v) = header_value(line, b"object ") {
            target = Some(v.to_string());
        } else if let Some(v) = header_value(line, b"type ") {
            target_type = Some(v.to_string());
        } else if let Some(v) = header_value(line, b"tag ") {
            tag_name = Some(v.to_string());
        } else if let Some(v) = header_value(line, b"tagger ") {
            tagger = Some(v.to_string());
        }
        pos = next;
    }

    let format = signature
        .as_deref()
        .map(detect_format)
        .unwrap_or(SignatureFormat::Unknown);

    ParsedTag {
        oid,
        target,
        target_type,
        tag_name,
        tagger,
        payload,
        signature,
        format,
    }
}

fn header_value<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a str> {
    if !line.starts_with(prefix) {
        return None;
    }
    let value = &line[prefix.len()..];
    let value = value.strip_suffix(b"\n").unwrap_or(value);
    std::str::from_utf8(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PGP_SIG: &str =
        "-----BEGIN PGP SIGNATURE-----\n\niQIzBAABCgAdFiEE\n-----END PGP SIGNATURE-----\n";

    /// Build a commit buffer with `gpgsig` whose continuation lines are
    /// space-prefixed, exactly as git writes them.
    fn commit_with_sig(sig: &str) -> Vec<u8> {
        let mut s = String::new();
        s.push_str("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n");
        s.push_str("parent 1111111111111111111111111111111111111111\n");
        s.push_str("author A <a@example.com> 1700000000 +0000\n");
        s.push_str("committer C <c@example.com> 1700000100 +0000\n");
        s.push_str("gpgsig ");
        for (index, line) in sig.split_inclusive('\n').enumerate() {
            if index > 0 {
                s.push(' ');
            }
            s.push_str(line);
        }
        s.push('\n');
        s.push_str("subject line\n");
        s.into_bytes()
    }

    #[test]
    fn unsigned_commit_payload_is_whole_buffer() {
        let buf = b"tree 4b82\nauthor A <a@b> 1 +0000\n\nmsg\n".to_vec();
        let (payload, sig) = split_commit(&buf, HashAlgorithm::Sha1);
        assert!(sig.is_none());
        assert_eq!(payload, buf);
    }

    #[test]
    fn signed_commit_strips_header_from_payload() {
        let buf = commit_with_sig(PGP_SIG);
        let (payload, sig) = split_commit(&buf, HashAlgorithm::Sha1);
        let sig = sig.expect("signature");
        assert_eq!(sig, PGP_SIG.as_bytes());
        let text = String::from_utf8(payload).unwrap();
        assert!(!text.contains("gpgsig"));
        assert!(text.contains("committer C <c@example.com> 1700000100 +0000\n\nsubject line\n"));
        assert_eq!(
            text,
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             parent 1111111111111111111111111111111111111111\n\
             author A <a@example.com> 1700000000 +0000\n\
             committer C <c@example.com> 1700000100 +0000\n\
             \n\
             subject line\n"
        );
    }

    #[test]
    fn foreign_gpgsig_header_is_excluded_from_payload() {
        // A sha1 repository must ignore the value of gpgsig-sha256, both for
        // the payload and for signature extraction.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"tree 4b82\n");
        buf.extend_from_slice(b"gpgsig-sha256 -----BEGIN PGP SIGNATURE-----\n \n AAAA\n -----END PGP SIGNATURE-----\n");
        buf.extend_from_slice(
            b"gpgsig -----BEGIN PGP SIGNATURE-----\n \n BBBB\n -----END PGP SIGNATURE-----\n",
        );
        buf.extend_from_slice(b"author A <a@b> 1 +0000\n");
        buf.extend_from_slice(b"committer C <c@d> 2 +0000\n\nmsg\n");
        let (payload, sig) = split_commit(&buf, HashAlgorithm::Sha1);
        assert_eq!(
            sig.unwrap(),
            b"-----BEGIN PGP SIGNATURE-----\n\nBBBB\n-----END PGP SIGNATURE-----\n"
        );
        let text = String::from_utf8(payload).unwrap();
        assert_eq!(
            text,
            "tree 4b82\nauthor A <a@b> 1 +0000\ncommitter C <c@d> 2 +0000\n\nmsg\n"
        );
    }

    #[test]
    fn tag_signature_is_split_at_armor_line() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"object 1111111111111111111111111111111111111111\n");
        buf.extend_from_slice(b"type commit\ntag v1\n");
        buf.extend_from_slice(b"tagger T <t@example.com> 1700000000 +0000\n\n");
        buf.extend_from_slice(b"message body\n");
        buf.extend_from_slice(PGP_SIG.as_bytes());
        let (payload, sig) = split_tag(&buf);
        assert_eq!(sig.unwrap(), PGP_SIG.as_bytes());
        assert!(payload.ends_with(b"message body\n"));
        let tag = parse_tag(&buf, "deadbeef".into());
        assert_eq!(tag.tag_name.as_deref(), Some("v1"));
        assert_eq!(
            tag.tagger.as_deref(),
            Some("T <t@example.com> 1700000000 +0000")
        );
        assert_eq!(tag.format, SignatureFormat::OpenPgp);
    }

    #[test]
    fn multiple_armor_blocks_use_last_one_like_git() {
        // git's parse_signed_buffer() remembers the LAST armor marker, so the
        // payload keeps the first block verbatim and the signature is the last.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"object 1111\ntype commit\ntag v1\n\n");
        buf.extend_from_slice(PGP_SIG.as_bytes());
        buf.extend_from_slice(PGP_SIG.as_bytes());
        let (payload, sig) = split_tag(&buf);
        assert_eq!(sig.as_deref(), Some(PGP_SIG.as_bytes()));
        // The first block remains part of the payload verbatim.
        assert!(payload.ends_with(PGP_SIG.as_bytes()));
        assert_eq!(
            payload
                .windows(PGP_SIG.len())
                .filter(|w| *w == PGP_SIG.as_bytes())
                .count(),
            1
        );
    }

    #[test]
    fn formats_are_detected_by_first_line() {
        assert_eq!(detect_format(SSH_SIGNATURE_BEGIN), SignatureFormat::Ssh);
        assert_eq!(detect_format(PGP_MESSAGE_BEGIN), SignatureFormat::OpenPgp);
        assert_eq!(
            detect_format(X509_SIGNED_MESSAGE_BEGIN),
            SignatureFormat::X509
        );
        assert_eq!(detect_format(b"junk"), SignatureFormat::Unknown);
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn byte(&mut self) -> u8 {
            self.next() as u8
        }
    }

    /// Commit and tag splitting run on bytes straight out of an untrusted
    /// object database, so they must tolerate anything.
    #[test]
    fn splitters_never_panic_on_random_bytes() {
        let mut rng = Rng(0x9E3779B97F4A7C15);
        for len in 0..400usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                // Bias towards the bytes that matter, so the interesting branches
                // (header names, continuation lines, armor lines) are hit.
                let b = match rng.next() % 8 {
                    0 => b'\n',
                    1 => b' ',
                    2 => b'g',
                    3 => b'-',
                    _ => rng.byte(),
                };
                buf.push(b);
            }
            let (_, _) = split_commit(&buf, HashAlgorithm::Sha1);
            let (_, _) = split_commit(&buf, HashAlgorithm::Sha256);
            let (_, _) = split_tag(&buf);
            let _ = parse_commit(&buf, "deadbeef".into(), HashAlgorithm::Sha1);
            let _ = parse_tag(&buf, "deadbeef".into());
            let _ = detect_format(&buf);
        }
    }

    #[test]
    fn splitters_never_panic_on_truncated_valid_commit() {
        let mut buf = Vec::new();
        buf.extend_from_slice(
            b"tree 4b82\nparent 1111\nauthor A <a@b> 1 +0000\ncommitter C <c@d> 2 +0000\n",
        );
        buf.extend_from_slice(
            b"gpgsig -----BEGIN PGP SIGNATURE-----\n \n AAAA\n -----END PGP SIGNATURE-----\n",
        );
        buf.extend_from_slice(b"\nmsg\n");
        for cut in 0..=buf.len() {
            let _ = split_commit(&buf[..cut], HashAlgorithm::Sha1);
            let _ = split_tag(&buf[..cut]);
        }
    }
}

#[cfg(test)]
mod differential {
    use super::*;

    /// git's tag payload, modelled from commit.c's `parse_signed_buffer()` and
    /// `remove_signature()`. Written with a separate shape (a list of removable
    /// byte ranges keyed by a 2-slot cursor) so it is an independent check on
    /// the implementation rather than a copy of it.
    fn git_tag_payload(buf: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
        let lines = |b: &[u8]| -> Vec<(usize, usize)> {
            let mut out = Vec::new();
            let mut pos = 0;
            while pos < b.len() {
                let next = memchr::memchr(b'\n', &b[pos..])
                    .map(|i| pos + i + 1)
                    .unwrap_or(b.len());
                out.push((pos, next));
                pos = next;
            }
            out
        };

        // parse_signed_buffer: the offset of the last armor-marker line.
        let mut match_at = buf.len();
        for (start, _) in lines(buf) {
            if detect_format(&buf[start..]) != SignatureFormat::Unknown {
                match_at = start;
            }
        }
        if match_at == buf.len() {
            return (buf.to_vec(), None);
        }
        let signature = buf[match_at..].to_vec();
        let payload = &buf[..match_at];

        // remove_signature over the payload.
        let lines = lines(payload);
        let mut slots: Vec<Option<(usize, usize)>> = vec![None; 2];
        let mut cursor = 0usize;
        let mut in_sig = false;
        let mut i = 0usize;
        while i < lines.len() {
            let (start, end) = lines[i];
            let blank = payload[start] == b'\n';
            let cont = payload[start] == b' ';
            let is_header = [b"gpgsig".as_slice(), b"gpgsig-sha256".as_slice()]
                .iter()
                .any(|h| {
                    payload[start..].starts_with(h) && payload.get(start + h.len()) == Some(&b' ')
                });
            let any_gpgsig = payload[start..].starts_with(b"gpgsig");

            if in_sig && cont {
                if cursor < slots.len() {
                    if let Some(slot) = slots[cursor].as_mut() {
                        slot.1 = end;
                    }
                }
            } else if any_gpgsig {
                if is_header {
                    if cursor < slots.len() {
                        slots[cursor] = Some((start, end));
                    }
                    in_sig = true;
                }
                // unrecognised gpgsig line: nothing changes at all
            } else {
                if blank {
                    // A blank line ends the scan and dumps the rest of the
                    // buffer, so advancing the cursor here is unobservable.
                    break;
                }
                if in_sig && cursor < slots.len() {
                    cursor += 1;
                }
                in_sig = false;
            }
            i += 1;
        }

        let mut out = payload.to_vec();
        let mut ranges: Vec<(usize, usize)> = slots.into_iter().flatten().collect();
        ranges.sort_by_key(|r| std::cmp::Reverse(r.0));
        for (s, e) in ranges {
            out.drain(s..e.min(out.len()).max(s));
        }
        (out, Some(signature))
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    /// Generate tag-shaped buffers mixing header lines, blank lines, armor
    /// blocks, `gpgsig` headers with continuations, and junk.
    fn gen_tag(rng: &mut Rng) -> Vec<u8> {
        let mut out = Vec::new();
        let pieces: [&[u8]; 12] = [
            b"object 1111\n",
            b"type commit\n",
            b"tag v1\n",
            b"tagger T <t@e> 1 +0000\n",
            b"\n",
            b"message text\n",
            b"-----BEGIN PGP SIGNATURE-----\n",
            b"AAAABBBB\n",
            b"-----END PGP SIGNATURE-----\n",
            b"gpgsig foo\n",
            b" continuation\n",
            b"gpgsig-sha256 bar\n",
        ];
        let count = (rng.next() % 14) as usize;
        for _ in 0..count {
            out.extend_from_slice(pieces[(rng.next() as usize) % pieces.len()]);
        }
        out
    }

    /// git's commit payload/signature split, modelled from
    /// `parse_buffer_signed_by_header()` in commit.c.
    ///
    /// git's shape is two-phase: first decide whether the line belongs to the
    /// signature (`sig != NULL`), then either append it to the signature or run
    /// the payload logic. Modelling it that way matters: a line that clears
    /// `other_signature` still falls through to the payload in the same
    /// iteration.
    fn git_commit_split(buf: &[u8], primary: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
        let mut payload = Vec::new();
        let mut signature: Option<Vec<u8>> = None;
        let mut in_signature = false;
        let mut other_signature = false;
        let mut pos = 0usize;
        while pos < buf.len() {
            let next = memchr::memchr(b'\n', &buf[pos..])
                .map(|i| pos + i + 1)
                .unwrap_or(buf.len());
            let line = &buf[pos..next];
            let continuation = line.first() == Some(&b' ');
            let is_primary = line.starts_with(primary) && line.get(primary.len()) == Some(&b' ');

            // Phase 1: is this line part of a signature?
            let mut consumed = false;
            if in_signature && continuation {
                signature
                    .get_or_insert_with(Vec::new)
                    .extend_from_slice(&line[1..]);
                consumed = true;
            } else if is_primary {
                signature
                    .get_or_insert_with(Vec::new)
                    .extend_from_slice(&line[primary.len() + 1..]);
                other_signature = false;
                consumed = true;
            } else if line.starts_with(b"gpgsig") {
                other_signature = true;
            } else if other_signature && !continuation {
                other_signature = false;
            }

            // Phase 2: signature, or payload.
            if consumed {
                in_signature = true;
            } else {
                if line.first() == Some(&b'\n') {
                    if !other_signature {
                        payload.extend_from_slice(&buf[pos..]);
                    }
                    break;
                }
                if !other_signature {
                    payload.extend_from_slice(line);
                }
                in_signature = false;
            }
            pos = next;
        }
        (payload, signature)
    }

    #[test]
    fn commit_split_matches_git_oracle() {
        let mut rng = Rng(0xDEAD_BEEF_1234_5678);
        let pieces: [&[u8]; 14] = [
            b"tree 4b82\n",
            b"parent 1111\n",
            b"author A <a@b> 1 +0000\n",
            b"committer C <c@d> 2 +0000\n",
            b"\n",
            b"message\n",
            b"gpgsig -----BEGIN PGP SIGNATURE-----\n",
            b" AAAA\n",
            b" -----END PGP SIGNATURE-----\n",
            b"gpgsig-sha256 -----BEGIN PGP SIGNATURE-----\n",
            b" BBBB\n",
            b"gpgsig-sha999\n",
            b" orphan-continuation\n",
            b"gpgsig \n",
        ];
        for _ in 0..200_000 {
            let count = (rng.next() % 16) as usize;
            let mut buf = Vec::new();
            for _ in 0..count {
                buf.extend_from_slice(pieces[(rng.next() as usize) % pieces.len()]);
            }
            for (primary, algo) in [
                (b"gpgsig".as_slice(), HashAlgorithm::Sha1),
                (b"gpgsig-sha256".as_slice(), HashAlgorithm::Sha256),
            ] {
                let (ours_payload, ours_sig) = split_commit(&buf, algo);
                let (git_payload, git_sig) = git_commit_split(&buf, primary);
                assert_eq!(
                    ours_sig,
                    git_sig,
                    "sig differs for {:?}",
                    String::from_utf8_lossy(&buf)
                );
                assert_eq!(
                    ours_payload,
                    git_payload,
                    "payload differs for {:?}",
                    String::from_utf8_lossy(&buf)
                );
            }
        }
    }

    #[test]
    fn tag_split_matches_git_oracle() {
        let mut rng = Rng(0x1234_5678_9ABC_DEF1);
        for _ in 0..200_000 {
            let buf = gen_tag(&mut rng);
            let (ours_payload, ours_sig) = split_tag(&buf);
            let (git_payload, git_sig) = git_tag_payload(&buf);
            assert_eq!(
                ours_sig,
                git_sig,
                "signature differs for {:?}",
                String::from_utf8_lossy(&buf)
            );
            assert_eq!(
                ours_payload,
                git_payload,
                "payload differs for {:?}",
                String::from_utf8_lossy(&buf)
            );
        }
    }
}
