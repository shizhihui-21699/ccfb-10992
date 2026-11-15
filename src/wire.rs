//! Wire-level primitives shared by the OpenPGP and SSH verifiers.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

/// Which hash function a signature or fingerprint request refers to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashKind {
    Sha1,
    Sha256,
    Sha512,
}

impl HashKind {
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashKind::Sha1 => Sha1::digest(data).to_vec(),
            HashKind::Sha256 => Sha256::digest(data).to_vec(),
            HashKind::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn digest_size(self) -> usize {
        match self {
            HashKind::Sha1 => 20,
            HashKind::Sha256 => 32,
            HashKind::Sha512 => 64,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            HashKind::Sha1 => "SHA1",
            HashKind::Sha256 => "SHA256",
            HashKind::Sha512 => "SHA512",
        }
    }
}

/// A bounded cursor over SSH wire-format data.
///
/// SSH (and the KRL file format built on it) encodes every variable-length
/// field as a big-endian `u32` length followed by that many bytes. Every read
/// is bounds checked, and any overrun is a hard parse error rather than a
/// silently truncated value.
pub struct SshReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SshReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| anyhow::anyhow!("length overflow"))?;
        if end > self.data.len() {
            anyhow::bail!(
                "truncated SSH data: need {n} bytes at offset {}, only {} remain",
                self.pos,
                self.remaining()
            );
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn take_bytes(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        self.take(n)
    }

    pub fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> anyhow::Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> anyhow::Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn string(&mut self) -> anyhow::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    pub fn utf8_string(&mut self) -> anyhow::Result<&'a str> {
        std::str::from_utf8(self.string()?).map_err(|e| anyhow::anyhow!("non-UTF-8 string: {e}"))
    }

    /// An `mpint` is a length-prefixed big-endian two's-complement integer.
    /// Only the magnitude matters for the places this auditor inspects it.
    pub fn mpint_bytes(&mut self) -> anyhow::Result<&'a [u8]> {
        let raw = self.string()?;
        Ok(raw.strip_prefix(&[0u8]).unwrap_or(raw))
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.data[self.pos..];
        self.pos = self.data.len();
        out
    }
}

/// Append an SSH `string` (u32 length + bytes) to `out`.
pub fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// Base64 without `=` padding, as used in OpenSSH fingerprints.
pub fn base64_unpadded(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(data)
}
