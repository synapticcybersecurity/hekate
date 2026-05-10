//! Streaming AEAD for attachments (M2.24).
//!
//! Plain XChaCha20-Poly1305 over a whole multi-megabyte file would force
//! both client and server to buffer the entire blob before AEAD verifies
//! anything. Resumable uploads compound the cost — a flaky network would
//! waste bandwidth re-uploading already-good chunks. So attachments use a
//! **chunked** AEAD format: the file is split into fixed-size plaintext
//! chunks (1 MiB), each independently sealed with a deterministic nonce
//! and chunk-index AAD. Decryption streams chunk-by-chunk; mid-file
//! corruption is caught at the next 1 MiB boundary.
//!
//! ## Wire format (`PMGRA1`)
//!
//! ```text
//! header (32 bytes):
//!   [0..6]   "PMGRA1"               -- magic
//!   [6]      u8 version              = 1
//!   [7]      u8 chunk_size_log2      = 20  (i.e. 1 MiB chunks; future-proof)
//!   [8..28]  20-byte random nonce_prefix
//!   [28..32] u32 reserved (LE, must be 0)
//!
//! body:
//!   chunk_0_ct || tag_0
//!   chunk_1_ct || tag_1
//!   ...
//!   chunk_{N-1}_ct || tag_{N-1}      -- final chunk, possibly short
//! ```
//!
//! Each chunk is XChaCha20-Poly1305:
//!   - key   = `att_key` (32 bytes random per attachment, wrapped under
//!     the cipher key as an EncString in `attachments.content_key`).
//!   - nonce = `nonce_prefix(20B) || chunk_index_be(4B)`. Random prefix
//!     makes nonces unique across files even with the same key
//!     (defense in depth — the key is per-attachment anyway).
//!     chunk_index in the nonce prevents reordering between chunks.
//!   - aad   = `attachment_id_bytes || chunk_index_be(4B) || final_flag(1B)`.
//!     `final_flag = 1` only on the last chunk. This is the
//!     **truncation guard**: a tail-stripping attack changes
//!     which chunk carries `final_flag = 1`, so verification
//!     fails on the new "last" chunk.
//!
//! Plaintext chunk size is fixed at 1 MiB (`chunk_size_log2 = 20`). The
//! last chunk may be shorter (1..=1MiB bytes); empty files are not
//! supported (clients should reject them at the UI layer). Ciphertext
//! chunk size = plaintext + 16-byte Poly1305 tag.
//!
//! ## Sizes
//!
//! For plaintext size P with chunk size C = 1 MiB:
//!
//! ```text
//! n_chunks  = ceil(P / C)
//! size_ct   = HEADER_LEN(32) + n_chunks * TAG_LEN(16) + P
//!           = 32 + ceil(P / 1048576) * 16 + P
//! ```
//!
//! Helpers `ciphertext_size_for` and `plaintext_size_for` compute these
//! exactly for quota enforcement and tus `Upload-Length` calculation.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

use crate::{Error, Result};

pub const MAGIC: &[u8; 6] = b"PMGRA1";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 32;
pub const NONCE_PREFIX_LEN: usize = 20;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
/// 1 MiB plaintext chunks. Hard-coded for v1; the header records the
/// log2 so a future format can change it without a separate version bump.
pub const CHUNK_SIZE_LOG2: u8 = 20;
pub const CHUNK_SIZE: usize = 1 << CHUNK_SIZE_LOG2;
pub const CIPHERTEXT_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_LEN;

/// Parsed PMGRA1 file header. Lives at offset 0 of every attachment ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeader {
    pub version: u8,
    pub chunk_size_log2: u8,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl FileHeader {
    pub fn random() -> Self {
        let mut prefix = [0u8; NONCE_PREFIX_LEN];
        OsRng.fill_bytes(&mut prefix);
        Self {
            version: VERSION,
            chunk_size_log2: CHUNK_SIZE_LOG2,
            nonce_prefix: prefix,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..6].copy_from_slice(MAGIC);
        out[6] = self.version;
        out[7] = self.chunk_size_log2;
        out[8..28].copy_from_slice(&self.nonce_prefix);
        // bytes 28..32 reserved = zeroed.
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::InvalidEncoding("attachment header too short".into()));
        }
        if &bytes[0..6] != MAGIC {
            return Err(Error::InvalidEncoding("attachment magic mismatch".into()));
        }
        let version = bytes[6];
        if version != VERSION {
            return Err(Error::InvalidEncoding(format!(
                "unknown attachment version {version}"
            )));
        }
        let chunk_size_log2 = bytes[7];
        if chunk_size_log2 != CHUNK_SIZE_LOG2 {
            return Err(Error::InvalidEncoding(format!(
                "unsupported chunk size log2 {chunk_size_log2}"
            )));
        }
        if bytes[28..32] != [0, 0, 0, 0] {
            return Err(Error::InvalidEncoding(
                "attachment header reserved bytes nonzero".into(),
            ));
        }
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&bytes[8..28]);
        Ok(Self {
            version,
            chunk_size_log2,
            nonce_prefix,
        })
    }
}

/// Build the per-chunk nonce: `nonce_prefix(20B) || chunk_index_be(4B)`.
fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_LEN], chunk_index: u32) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[NONCE_PREFIX_LEN..].copy_from_slice(&chunk_index.to_be_bytes());
    n
}

/// AAD = `attachment_id_bytes || chunk_index_be(4B) || final_flag(1B)`.
/// The final-flag bit makes truncation of trailing chunks detectable —
/// an attacker who drops the last chunk forces the new last chunk to
/// have AAD with `final_flag = 0`, breaking AEAD verification.
fn chunk_aad(attachment_id: &[u8], chunk_index: u32, final_chunk: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(attachment_id.len() + 5);
    aad.extend_from_slice(attachment_id);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.push(if final_chunk { 1 } else { 0 });
    aad
}

/// Compute the exact ciphertext size for a plaintext of `pt_size` bytes
/// (header + per-chunk Poly1305 tags + plaintext bytes).
pub fn ciphertext_size_for(pt_size: u64) -> u64 {
    if pt_size == 0 {
        // Defined for callers that want to check empty-file rejection
        // at quota time; the actual encoder rejects pt_size == 0.
        return HEADER_LEN as u64;
    }
    let n_chunks = pt_size.div_ceil(CHUNK_SIZE as u64);
    HEADER_LEN as u64 + n_chunks * TAG_LEN as u64 + pt_size
}

/// Inverse of `ciphertext_size_for`. Returns the plaintext size that
/// produced the given ciphertext size, or `Err` if the ciphertext size
/// can't correspond to any valid chunked layout.
pub fn plaintext_size_for(ct_size: u64) -> Result<u64> {
    if ct_size < HEADER_LEN as u64 {
        return Err(Error::InvalidEncoding(
            "ciphertext smaller than header".into(),
        ));
    }
    let body = ct_size - HEADER_LEN as u64;
    if body == 0 {
        return Ok(0);
    }
    // body = n_chunks * TAG_LEN + pt_size
    // pt_size in [(n-1)*C + 1, n*C]; equivalently
    // body in   [(n-1)*C + n*TAG + 1, n*C + n*TAG]
    // => body / (C + TAG) rounded up gives n_chunks (for body > 0).
    let per_full = (CHUNK_SIZE + TAG_LEN) as u64;
    let n_chunks = body.div_ceil(per_full);
    let total_tags = n_chunks * TAG_LEN as u64;
    if body < total_tags {
        return Err(Error::InvalidEncoding(
            "ciphertext size implies negative plaintext".into(),
        ));
    }
    let pt = body - total_tags;
    // Sanity: plaintext must fit exactly into n_chunks * CHUNK_SIZE.
    let max_pt = n_chunks * CHUNK_SIZE as u64;
    let min_pt = (n_chunks - 1) * CHUNK_SIZE as u64 + 1;
    if pt < min_pt || pt > max_pt {
        return Err(Error::InvalidEncoding(
            "ciphertext size does not match any valid chunk count".into(),
        ));
    }
    Ok(pt)
}

/// One-shot encrypt — useful for unit tests and small plaintexts. For
/// large files clients should use the streaming flow (see CLI's `attach
/// upload`): compute plaintext chunks lazily and stream them through tus
/// PATCH without buffering the whole file.
pub fn encrypt(att_key: &[u8; 32], attachment_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.is_empty() {
        return Err(Error::InvalidEncoding(
            "empty attachment plaintext is not supported".into(),
        ));
    }
    let header = FileHeader::random();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(att_key));

    let n_chunks = plaintext.len().div_ceil(CHUNK_SIZE);
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + n_chunks * TAG_LEN);
    out.extend_from_slice(&header.encode());
    for (i, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        let chunk_index = i as u32;
        let final_chunk = i + 1 == n_chunks;
        let nonce = chunk_nonce(&header.nonce_prefix, chunk_index);
        let aad = chunk_aad(attachment_id, chunk_index, final_chunk);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        out.extend_from_slice(&ct);
    }
    Ok(out)
}

/// One-shot decrypt — verifies header, every chunk's tag, AAD binding,
/// and the truncation guard. Streaming consumers should use
/// `Decryptor::next_chunk` so they don't need to buffer the whole file.
pub fn decrypt(att_key: &[u8; 32], attachment_id: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let header = FileHeader::decode(ciphertext)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(att_key));
    let body = &ciphertext[HEADER_LEN..];
    if body.is_empty() {
        return Err(Error::InvalidEncoding("attachment body empty".into()));
    }

    // Number of ciphertext chunks. Each is up to CIPHERTEXT_CHUNK_SIZE,
    // last is short. Walk left-to-right; we know we're on the final
    // chunk iff the remaining bytes are <= CIPHERTEXT_CHUNK_SIZE.
    let mut out = Vec::new();
    let mut p = body;
    let mut chunk_index: u32 = 0;
    while !p.is_empty() {
        let take = p.len().min(CIPHERTEXT_CHUNK_SIZE);
        let final_chunk = take == p.len();
        let nonce = chunk_nonce(&header.nonce_prefix, chunk_index);
        let aad = chunk_aad(attachment_id, chunk_index, final_chunk);
        let pt = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &p[..take],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        out.extend_from_slice(&pt);
        p = &p[take..];
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| Error::InvalidEncoding("attachment too many chunks".into()))?;
    }
    Ok(out)
}

/// Streaming encoder. Feed plaintext chunks of any size; receive
/// ciphertext bytes incrementally. Caller must hold the file open and
/// provide chunks **in order**. See CLI usage in `hekate attach upload`.
pub struct Encryptor {
    cipher: XChaCha20Poly1305,
    attachment_id: Vec<u8>,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_index: u32,
    pending: Vec<u8>,
    /// True after `finalize()` is called.
    finished: bool,
}

impl Encryptor {
    /// Start a new encryption stream. Emits the file header bytes — the
    /// caller writes them at the start of the output.
    pub fn new(att_key: &[u8; 32], attachment_id: &[u8]) -> (Self, [u8; HEADER_LEN]) {
        let header = FileHeader::random();
        let header_bytes = header.encode();
        (
            Self {
                cipher: XChaCha20Poly1305::new(Key::from_slice(att_key)),
                attachment_id: attachment_id.to_vec(),
                nonce_prefix: header.nonce_prefix,
                chunk_index: 0,
                pending: Vec::with_capacity(CHUNK_SIZE),
                finished: false,
            },
            header_bytes,
        )
    }

    /// Push plaintext bytes; returns ciphertext bytes ready to write
    /// (zero or more 1 MiB-encrypted chunks). The encoder buffers up to
    /// one chunk-worth of plaintext internally; call `finalize` to flush
    /// the trailing chunk with the final-flag bit set.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::InvalidEncoding("encryptor already finished".into()));
        }
        let mut out = Vec::new();
        self.pending.extend_from_slice(plaintext);
        // Emit any complete non-final chunks. We must keep at least one
        // byte unflushed so we know whether the next push (or finalize)
        // is producing the final chunk; emit only when buffer >= 2*CHUNK_SIZE.
        while self.pending.len() > CHUNK_SIZE {
            let take = CHUNK_SIZE;
            // SAFETY: this is a non-final chunk (more bytes remain).
            let nonce = chunk_nonce(&self.nonce_prefix, self.chunk_index);
            let aad = chunk_aad(&self.attachment_id, self.chunk_index, false);
            let chunk = self
                .cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &self.pending[..take],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Crypto)?;
            out.extend_from_slice(&chunk);
            self.pending.drain(..take);
            self.chunk_index = self
                .chunk_index
                .checked_add(1)
                .ok_or_else(|| Error::InvalidEncoding("too many chunks".into()))?;
        }
        Ok(out)
    }

    /// Flush the pending buffer as the final chunk (with `final_flag = 1`
    /// in the AAD). Returns the trailing ciphertext bytes the caller must
    /// append. Calling `push` after `finalize` is an error.
    pub fn finalize(mut self) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::InvalidEncoding("encryptor already finished".into()));
        }
        if self.pending.is_empty() {
            // Empty plaintext — hekate does not allow zero-byte attachments.
            return Err(Error::InvalidEncoding(
                "no plaintext written before finalize".into(),
            ));
        }
        self.finished = true;
        let nonce = chunk_nonce(&self.nonce_prefix, self.chunk_index);
        let aad = chunk_aad(&self.attachment_id, self.chunk_index, true);
        let chunk = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &self.pending,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        Ok(chunk)
    }
}

/// Generate a fresh per-attachment 32-byte key. Wrap with the cipher key
/// using `EncString::encrypt_xc20p` and AAD `attachment_id || "key" || cipher_id`
/// before sending to the server.
pub fn generate_attachment_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

/// AAD bound to the per-attachment key wrap. Mirrors the cipher-field
/// AAD pattern in `hekate-cli/src/crypto.rs::aad_*`: bind the wrap to its
/// (cipher, attachment) location so a server can't substitute another
/// attachment's wrapped key.
pub fn att_key_wrap_aad(attachment_id: &str, cipher_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(attachment_id.len() + 4 + cipher_id.len());
    aad.extend_from_slice(attachment_id.as_bytes());
    aad.extend_from_slice(b"|key|");
    aad.extend_from_slice(cipher_id.as_bytes());
    aad
}

/// BLAKE3 of arbitrary bytes, base64-no-pad encoded. Used as
/// `attachments.content_hash_b3` — server verifies on finalize, clients
/// verify after download.
pub fn content_hash_b3(bytes: &[u8]) -> String {
    let h = blake3::hash(bytes);
    STANDARD_NO_PAD.encode(h.as_bytes())
}

/// Hasher for streaming integrity. Update with ciphertext as it flows
/// past, then `finalize_b64`.
#[derive(Default)]
pub struct Blake3Stream(blake3::Hasher);

impl Blake3Stream {
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub fn finalize_b64(self) -> String {
        STANDARD_NO_PAD.encode(self.0.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn round_trip_small_plaintext() {
        let pt = b"hello attachments";
        let ct = encrypt(&key(), b"att-1", pt).unwrap();
        // Header + one chunk (short final).
        assert_eq!(ct.len(), HEADER_LEN + pt.len() + TAG_LEN);
        let pt2 = decrypt(&key(), b"att-1", &ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn round_trip_exact_chunk_boundary() {
        // Plaintext = exactly one chunk. Decrypt path treats it as final
        // because no body bytes remain after the first ciphertext chunk.
        let pt = vec![0xab; CHUNK_SIZE];
        let ct = encrypt(&key(), b"att-2", &pt).unwrap();
        assert_eq!(ct.len(), HEADER_LEN + CHUNK_SIZE + TAG_LEN);
        let pt2 = decrypt(&key(), b"att-2", &ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn round_trip_two_full_chunks_plus_short_tail() {
        // 2.5 chunks worth of plaintext: two full chunks + a short final.
        let pt: Vec<u8> = (0..(CHUNK_SIZE * 2 + 17))
            .map(|i| (i & 0xff) as u8)
            .collect();
        let ct = encrypt(&key(), b"att-3", &pt).unwrap();
        let expected = HEADER_LEN + pt.len() + 3 * TAG_LEN;
        assert_eq!(ct.len(), expected);
        let pt2 = decrypt(&key(), b"att-3", &ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn truncation_at_final_chunk_is_detected() {
        // Drop the last chunk's ct + tag → previous chunk now becomes
        // the last bytes of body, but its AAD was written with
        // final_flag = 0 → AEAD verify fails.
        let pt: Vec<u8> = (0..(CHUNK_SIZE * 2 + 100)).map(|i| i as u8).collect();
        let ct = encrypt(&key(), b"att-4", &pt).unwrap();
        let truncated_len = HEADER_LEN + 2 * CIPHERTEXT_CHUNK_SIZE; // chop final
        let err = decrypt(&key(), b"att-4", &ct[..truncated_len]).unwrap_err();
        assert!(matches!(err, Error::Crypto));
    }

    #[test]
    fn reordering_chunks_is_detected() {
        // Swap two ciphertext chunks → chunk_index in the nonce + AAD
        // forces AEAD verify to fail.
        let pt: Vec<u8> = (0..(CHUNK_SIZE * 2 + 50)).map(|i| i as u8).collect();
        let mut ct = encrypt(&key(), b"att-5", &pt).unwrap();
        let body_off = HEADER_LEN;
        // Each non-final ciphertext chunk is CIPHERTEXT_CHUNK_SIZE bytes.
        let a_start = body_off;
        let b_start = body_off + CIPHERTEXT_CHUNK_SIZE;
        let mut a = ct[a_start..a_start + CIPHERTEXT_CHUNK_SIZE].to_vec();
        let mut b = ct[b_start..b_start + CIPHERTEXT_CHUNK_SIZE].to_vec();
        ct[a_start..a_start + CIPHERTEXT_CHUNK_SIZE].copy_from_slice(&b);
        ct[b_start..b_start + CIPHERTEXT_CHUNK_SIZE].copy_from_slice(&a);
        let _ = (&mut a, &mut b);
        let err = decrypt(&key(), b"att-5", &ct).unwrap_err();
        assert!(matches!(err, Error::Crypto));
    }

    #[test]
    fn wrong_attachment_id_rejected() {
        let pt = b"x";
        let ct = encrypt(&key(), b"alice", pt).unwrap();
        // Different attachment_id flips the AAD.
        assert!(decrypt(&key(), b"bob", &ct).is_err());
    }

    #[test]
    fn header_corruption_rejected() {
        let ct = encrypt(&key(), b"att", b"y").unwrap();
        let mut bad = ct.clone();
        bad[0] ^= 0x01; // flip magic
        assert!(decrypt(&key(), b"att", &bad).is_err());
        let mut bad2 = ct.clone();
        bad2[6] = 99; // flip version
        assert!(decrypt(&key(), b"att", &bad2).is_err());
    }

    #[test]
    fn empty_plaintext_rejected() {
        assert!(encrypt(&key(), b"att", b"").is_err());
    }

    #[test]
    fn ciphertext_size_matches_helper() {
        for pt_size in [1u64, 100, 1023, CHUNK_SIZE as u64, CHUNK_SIZE as u64 + 1] {
            let pt = vec![0u8; pt_size as usize];
            let ct = encrypt(&key(), b"att", &pt).unwrap();
            assert_eq!(ct.len() as u64, ciphertext_size_for(pt_size));
            // Inverse holds.
            assert_eq!(plaintext_size_for(ct.len() as u64).unwrap(), pt_size);
        }
    }

    #[test]
    fn streaming_encrypt_matches_one_shot() {
        let pt: Vec<u8> = (0..(CHUNK_SIZE + 7)).map(|i| (i & 0xff) as u8).collect();
        // Streaming: split into many small writes.
        let (mut enc, header) = Encryptor::new(&key(), b"att-stream");
        let mut streaming_ct = header.to_vec();
        for piece in pt.chunks(123) {
            streaming_ct.extend(enc.push(piece).unwrap());
        }
        streaming_ct.extend(enc.finalize().unwrap());

        // Decrypt with the one-shot path.
        let pt2 = decrypt(&key(), b"att-stream", &streaming_ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn content_hash_is_stable() {
        let h1 = content_hash_b3(b"abc");
        let h2 = content_hash_b3(b"abc");
        assert_eq!(h1, h2);
        assert_ne!(content_hash_b3(b"abc"), content_hash_b3(b"abd"));

        // Streaming hasher matches one-shot.
        let mut s = Blake3Stream::new();
        s.update(b"a");
        s.update(b"bc");
        assert_eq!(s.finalize_b64(), h1);
    }

    #[test]
    fn att_key_wrap_aad_is_distinct_per_location() {
        let a = att_key_wrap_aad("att-1", "cipher-1");
        let b = att_key_wrap_aad("att-1", "cipher-2");
        let c = att_key_wrap_aad("att-2", "cipher-1");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn plaintext_size_for_rejects_invalid() {
        // Below header.
        assert!(plaintext_size_for(10).is_err());
        // Header only is OK (treated as zero plaintext for the helper;
        // encrypt() still rejects).
        assert_eq!(plaintext_size_for(HEADER_LEN as u64).unwrap(), 0);
    }
}
