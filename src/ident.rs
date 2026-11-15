//! Commit/tag identity parsing, mirroring git's `split_ident_line`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ident {
    pub name: String,
    pub email: String,
    pub timestamp: i64,
    pub tz_offset_minutes: Option<i32>,
    pub raw: String,
}

impl Ident {
    /// Parse an identity line such as `Alice <alice@example.com> 1700000000 +0800`.
    ///
    /// Deliberately tolerant: git rejects malformed idents during commit parsing,
    /// but for an audit tool we would rather report the commit than skip it.
    pub fn parse(raw: &str) -> Option<Ident> {
        let raw = raw.trim_end_matches(['\n', '\r']);
        let lt = raw.find('<')?;
        let gt = raw[lt + 1..].find('>').map(|i| lt + 1 + i)?;
        let name = raw[..lt].trim_end().to_string();
        let email = raw[lt + 1..gt].to_string();
        let rest = raw[gt + 1..].trim_start();
        let (ts_str, tz_str) = match rest.find(' ') {
            Some(i) => (&rest[..i], rest[i + 1..].trim()),
            None => (rest, ""),
        };
        let timestamp: i64 = ts_str.parse().ok()?;
        let tz_offset_minutes = parse_tz(tz_str);
        Some(Ident {
            name,
            email,
            timestamp,
            tz_offset_minutes,
            raw: raw.to_string(),
        })
    }
}

fn parse_tz(tz: &str) -> Option<i32> {
    let bytes = tz.as_bytes();
    if bytes.len() < 5 {
        return None;
    }
    let sign = match bytes[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let hours: i32 = std::str::from_utf8(&bytes[1..3]).ok()?.parse().ok()?;
    let minutes: i32 = std::str::from_utf8(&bytes[3..5]).ok()?.parse().ok()?;
    Some(sign * (hours * 60 + minutes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_ident() {
        let i = Ident::parse("Alice A. <alice@example.com> 1700000000 +0800").unwrap();
        assert_eq!(i.name, "Alice A.");
        assert_eq!(i.email, "alice@example.com");
        assert_eq!(i.timestamp, 1700000000);
        assert_eq!(i.tz_offset_minutes, Some(480));
    }

    #[test]
    fn parses_empty_name_and_negative_tz() {
        let i = Ident::parse(" <a@b> 1 -0530").unwrap();
        assert_eq!(i.name, "");
        assert_eq!(i.timestamp, 1);
        assert_eq!(i.tz_offset_minutes, Some(-330));
    }

    #[test]
    fn rejects_missing_email() {
        assert!(Ident::parse("Alice 1700000000 +0000").is_none());
    }
}
