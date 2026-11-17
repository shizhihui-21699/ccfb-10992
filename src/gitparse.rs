//! Git-compatible parsing of signed commits.
//!
//! Git stores a commit signature as a multi-line `gpgsig` header inside the
//! commit object.  Verification therefore needs two things recovered from the
//! raw object:
//!
//! * the *payload* — the commit with the signature header removed, and
//! * the *signature* — the armored blob, de-indented.
//!
//! This mirrors `parse_buffer_signed_by_header()` and `remove_signature()` in
//! git's `commit.c` so the reconstructed payload hashes to exactly the same
//! bytes git would hand to gpg / ssh-keygen.

use crate::types::SigKind;

/// Armor headers git recognises, in `get_format_by_sig()` order.
const OPENPGP_SIG: &str = "-----BEGIN PGP SIGNATURE-----";
const OPENPGP_MSG: &str = "-----BEGIN PGP MESSAGE-----";
const X509_SIG: &str = "-----BEGIN SIGNED MESSAGE-----";
const SSH_SIG: &str = "-----BEGIN SSH SIGNATURE-----";

/// A commit split into verifiable parts.
#[derive(Debug, Clone)]
pub struct SignedCommit {
    /// Payload exactly as git reconstructs it (signature header removed).
    pub payload: Vec<u8>,
    /// Armored signature text, or `None` when the commit is unsigned.
    pub signature: Option<Vec<u8>>,
    /// Format of the signature armor, when one is present.
    pub kind: Option<SigKind>,
    /// Committer timestamp from the payload, in seconds since the epoch.
    pub commit_time: Option<i64>,
    /// Why the object could not be interpreted, if it could not.
    pub problem: Option<String>,
}

impl SignedCommit {
    /// True when the commit carries a signature header for this hash format.
    #[allow(dead_code)] // used by the unit tests
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

/// Detects the signature format from the first line of the armor.
///
/// Git's `get_format_by_sig()` dies on unknown armor; an audit should report it
/// instead, so unknown material is surfaced as [`SigKind::Unknown`].
pub fn detect_kind(sig: &[u8]) -> SigKind {
    let head_len = sig.len().min(64);
    let head = String::from_utf8_lossy(&sig[..head_len]);
    if head.starts_with(OPENPGP_SIG) || head.starts_with(OPENPGP_MSG) {
        SigKind::OpenPgp
    } else if head.starts_with(SSH_SIG) {
        SigKind::Ssh
    } else if head.starts_with(X509_SIG) {
        SigKind::X509
    } else {
        SigKind::Unknown
    }
}

/// Which `gpgsig`-family header carries the signature for this repository.
///
/// SHA-1 repositories use `gpgsig`; SHA-256 repositories use `gpgsig-sha256`.
/// A signature for the *other* algorithm is excluded from the payload — it is
/// not part of what was signed.
fn signature_header(hash_algo: HashAlgo) -> &'static str {
    match hash_algo {
        HashAlgo::Sha1 => "gpgsig",
        HashAlgo::Sha256 => "gpgsig-sha256",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Sha1,
    Sha256,
}

/// Splits a raw commit object into payload, signature and metadata.
pub fn parse_commit(raw: &[u8], hash_algo: HashAlgo) -> SignedCommit {
    let header = signature_header(hash_algo);
    let header_bytes = header.as_bytes();

    let mut payload: Vec<u8> = Vec::with_capacity(raw.len());
    let mut signature: Vec<u8> = Vec::new();
    let mut saw_signature = false;
    let mut in_signature = false;
    // Set while skipping a signature that belongs to a *different* hash
    // algorithm; its continuation lines must not leak into the payload.
    let mut other_signature = false;

    let mut pos = 0usize;
    while pos < raw.len() {
        let mut next = match memchr(b'\n', &raw[pos..]) {
            Some(off) => pos + off + 1,
            None => raw.len(),
        };
        let line = &raw[pos..next];

        let mut sig_start: Option<usize> = None;
        if in_signature && line[0] == b' ' {
            sig_start = Some(1);
        } else if line.starts_with(header_bytes)
            && line.get(header_bytes.len()).copied() == Some(b' ')
        {
            sig_start = Some(header_bytes.len() + 1);
            other_signature = false;
        } else if line.starts_with(b"gpgsig") {
            other_signature = true;
        } else if other_signature && line[0] != b' ' {
            other_signature = false;
        }

        match sig_start {
            Some(start) => {
                // Git copies the remainder of the line *including* the newline.
                signature.extend_from_slice(&line[start..]);
                saw_signature = true;
                in_signature = true;
            }
            None => {
                // A blank line terminates the header block: everything from
                // here on belongs to the payload untouched.
                if line[0] == b'\n' {
                    next = raw.len();
                }
                if !other_signature {
                    payload.extend_from_slice(&raw[pos..next]);
                }
                in_signature = false;
            }
        }
        pos = next;
    }

    let signature = if saw_signature { Some(signature) } else { None };
    let kind = signature.as_deref().map(detect_kind);

    let (commit_time, problem) = match commit_time_from_payload(&payload) {
        Ok(t) => (Some(t), None),
        Err(e) => (None, Some(e)),
    };

    SignedCommit {
        payload,
        signature,
        kind,
        commit_time,
        problem,
    }
}

/// Extracts the committer timestamp from a commit payload.
///
/// Mirrors git's `find_commit_header("committer")` + `split_ident_line()` +
/// `parse_timestamp()`: the timestamp is the numeric field that follows the
/// closing `>` of the identity.
pub fn commit_time_from_payload(payload: &[u8]) -> Result<i64, String> {
    let line = find_header(payload, b"committer")
        .ok_or_else(|| "commit has no committer header".to_string())?;
    parse_ident_timestamp(line).ok_or_else(|| "committer header has no parsable timestamp".to_string())
}

/// Returns the value of `name` in a commit header block (first match).
fn find_header<'a>(buf: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut start = 0usize;
    while start < buf.len() {
        let end = match memchr(b'\n', &buf[start..]) {
            Some(off) => start + off,
            None => buf.len(),
        };
        let line = &buf[start..end];
        if line.is_empty() {
            break; // end of headers
        }
        if line.len() > name.len()
            && &line[..name.len()] == name
            && line[name.len()] == b' '
        {
            return Some(&line[name.len() + 1..]);
        }
        start = end + 1;
    }
    None
}

/// Parses `Name <email> 1704240000 +0800` and returns `1704240000`.
fn parse_ident_timestamp(ident: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(ident).ok()?;
    let rest = match text.rfind('>') {
        Some(idx) => &text[idx + 1..],
        // Tolerate identities without angle brackets: fall back to the second
        // whitespace-separated field from the end.
        None => {
            let mut parts: Vec<&str> = text.split_whitespace().collect();
            parts.pop()?; // timezone
            parts.pop()? // timestamp
        }
    };
    let mut fields = rest.split_whitespace();
    let ts = fields.next()?;
    // Reject non-numeric junk rather than silently truncating.
    let digits = ts.strip_prefix('-').unwrap_or(ts);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    ts.parse::<i64>().ok()
}

/// Commit metadata extracted from the payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitMeta {
    pub tree: Option<String>,
    pub parents: Vec<String>,
    pub author: Option<String>,
    pub committer: Option<String>,
    /// Committer timestamp in epoch seconds.
    pub commit_time: Option<i64>,
    /// First line of the commit message.
    pub subject: String,
}

/// Extracts the fields an audit reports on.
pub fn parse_meta(payload: &[u8]) -> CommitMeta {
    let mut meta = CommitMeta::default();
    let mut start = 0usize;
    let mut body_at = payload.len();

    while start < payload.len() {
        let end = match memchr(b'\n', &payload[start..]) {
            Some(off) => start + off,
            None => payload.len(),
        };
        let line = &payload[start..end];
        if line.is_empty() {
            body_at = (end + 1).min(payload.len());
            break;
        }
        // Continuation lines of a multi-line header are not fields we need.
        if line[0] == b' ' {
            start = end + 1;
            continue;
        }
        let (name, value) = match line.iter().position(|&b| b == b' ') {
            Some(i) => (&line[..i], &line[i + 1..]),
            None => (line, &line[line.len()..]),
        };
        let value_str = String::from_utf8_lossy(value).to_string();
        match name {
            b"tree" => meta.tree = Some(value_str),
            b"parent" => meta.parents.push(value_str),
            b"author" => meta.author = Some(value_str),
            b"committer" => {
                meta.commit_time = parse_ident_timestamp(value);
                meta.committer = Some(value_str);
            }
            _ => {}
        }
        start = end + 1;
    }

    let body = &payload[body_at.min(payload.len())..];
    // Strip the single blank separator line, then take the first message line.
    let text = String::from_utf8_lossy(body);
    let mut lines = text.lines();
    // `body` starts right after the header/body separator, so the first line is
    // already message content.
    if let Some(first) = lines.next() {
        let first = first.trim();
        if first.is_empty() {
            // Tolerate an extra blank line.
            meta.subject = lines.next().map(|l| l.trim().to_string()).unwrap_or_default();
        } else {
            meta.subject = first.to_string();
        }
    }
    meta
}

/// Minimal `memchr` so the crate does not pull in another dependency.
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_commit(msg: &str) -> Vec<u8> {
        format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1704067200 +0000\n\
             committer C O Mitter <c@example.com> 1704153600 +0800\n\
             \n\
             {msg}\n"
        )
        .into_bytes()
    }

    #[test]
    fn unsigned_commit_has_no_signature() {
        let raw = simple_commit("hello");
        let parsed = parse_commit(&raw, HashAlgo::Sha1);
        assert!(!parsed.is_signed());
        assert_eq!(parsed.payload, raw);
        assert_eq!(parsed.commit_time, Some(1704153600));
        assert!(parsed.problem.is_none());
    }

    #[test]
    fn signature_is_removed_from_payload() {
        let raw = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                   author A U Thor <a@example.com> 1704067200 +0000\n\
                   committer C O Mitter <c@example.com> 1704153600 +0800\n\
                   gpgsig -----BEGIN PGP SIGNATURE-----\n \
                    \n \
                    iQEzBAABCAAdFiEE\n \
                    =abcd\n \
                    -----END PGP SIGNATURE-----\n\
                   \n\
                   subject\n"
            .as_bytes()
            .to_vec();
        let parsed = parse_commit(&raw, HashAlgo::Sha1);
        let sig = parsed.signature.expect("signature");
        assert_eq!(parsed.kind, Some(SigKind::OpenPgp));
        assert_eq!(
            String::from_utf8(sig).unwrap(),
            "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEE\n=abcd\n-----END PGP SIGNATURE-----\n"
        );
        assert_eq!(
            String::from_utf8(parsed.payload).unwrap(),
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1704067200 +0000\n\
             committer C O Mitter <c@example.com> 1704153600 +0800\n\
             \n\
             subject\n"
        );
        // The committer timestamp lives in the payload, not the signature.
        assert_eq!(parsed.commit_time, Some(1704153600));
    }

    #[test]
    fn other_hash_algo_signature_is_excluded_from_payload() {
        // A SHA-1 repository carrying a stray gpgsig-sha256 header: git treats
        // the commit as unsigned and strips the stray header from the payload.
        let raw = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                   author A U Thor <a@example.com> 1704067200 +0000\n\
                   committer C O Mitter <c@example.com> 1704153600 +0800\n\
                   gpgsig-sha256 -----BEGIN SSH SIGNATURE-----\n \
                    AAAAB\n \
                    -----END SSH SIGNATURE-----\n\
                   \n\
                   subject\n"
            .as_bytes()
            .to_vec();
        let parsed = parse_commit(&raw, HashAlgo::Sha1);
        assert!(!parsed.is_signed());
        let payload = String::from_utf8(parsed.payload).unwrap();
        assert!(!payload.contains("gpgsig-sha256"));
        assert!(payload.ends_with("subject\n"));
    }

    #[test]
    fn ssh_signature_detected() {
        let raw = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                   author A U Thor <a@example.com> 1704067200 +0000\n\
                   committer C O Mitter <c@example.com> 1704153600 +0000\n\
                   gpgsig -----BEGIN SSH SIGNATURE-----\n \
                    U1NIU0lH\n \
                    -----END SSH SIGNATURE-----\n\
                   \n\
                   subject\n"
            .as_bytes()
            .to_vec();
        let parsed = parse_commit(&raw, HashAlgo::Sha1);
        assert_eq!(parsed.kind, Some(SigKind::Ssh));
    }

    #[test]
    fn timestamp_is_parsed_from_ident() {
        assert_eq!(
            parse_ident_timestamp(b"C O Mitter <c@example.com> 1704153600 +0800"),
            Some(1704153600)
        );
        // No angle brackets: fall back to the field before the timezone.
        assert_eq!(parse_ident_timestamp(b"Name 1704153600 +0000"), Some(1704153600));
        assert_eq!(parse_ident_timestamp(b"Name <a@b> not-a-time +0000"), None);
        assert_eq!(parse_ident_timestamp(b""), None);
    }

    #[test]
    fn missing_committer_is_reported() {
        let raw = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@b> 1 +0000\n\nmsg\n";
        let parsed = parse_commit(raw, HashAlgo::Sha1);
        assert!(parsed.problem.is_some());
        assert_eq!(parsed.commit_time, None);
    }

    #[test]
    fn crlf_style_continuation_still_parses() {
        let raw = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                    committer C <c@example.com> 1704153600 +0000\n\
                    gpgsig -----BEGIN PGP SIGNATURE-----\n\tabc\n\
                    \n\
                    subject\n";
        let raw = raw.to_vec();
        let parsed = parse_commit(&raw, HashAlgo::Sha1);
        // The tab-led line is not a continuation, so the signature ends after
        // the first armor line — exactly as git reconstructs it.
        let sig = String::from_utf8(parsed.signature.unwrap()).unwrap();
        assert_eq!(sig, "-----BEGIN PGP SIGNATURE-----\n");
        assert!(String::from_utf8(parsed.payload).unwrap().contains("\tabc\n"));
    }

    #[test]
    fn meta_reports_fields_and_subject() {
        let raw = simple_commit("first line\n\nbody text\n");
        let parsed = parse_commit(&raw, HashAlgo::Sha1);
        let meta = parse_meta(&parsed.payload);
        assert_eq!(
            meta.tree.as_deref(),
            Some("4b825dc642cb6eb9a060e54bf8d69288fbee4904")
        );
        assert!(meta.parents.is_empty());
        assert_eq!(meta.author.as_deref(), Some("A U Thor <a@example.com> 1704067200 +0000"));
        assert_eq!(meta.commit_time, Some(1704153600));
        assert_eq!(meta.subject, "first line");
    }

    #[test]
    fn meta_collects_merge_parents() {
        let raw = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                    parent 1111111111111111111111111111111111111111\n\
                    parent 2222222222222222222222222222222222222222\n\
                    committer C <c@example.com> 1704153600 +0000\n\
                    \n\
                    merge two branches\n";
        let meta = parse_meta(raw);
        assert_eq!(meta.parents.len(), 2);
        assert_eq!(meta.subject, "merge two branches");
    }

    #[test]
    fn meta_tolerates_extra_blank_line() {
        let raw = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                    committer C <c@example.com> 1704153600 +0000\n\
                    \n\
                    \n\
                    subject after blank\n";
        assert_eq!(parse_meta(raw).subject, "subject after blank");
    }
}

