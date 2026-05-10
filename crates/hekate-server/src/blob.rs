//! Blob storage abstraction for attachments (M2.24).
//!
//! The `BlobStore` trait isolates the storage backend from the tus
//! upload protocol and the routing layer. M2.24 ships only a local-FS
//! impl; M2.24a will add an `object_store`-backed S3/MinIO impl behind
//! the same trait, switched by config.
//!
//! Why a trait instead of OpenDAL: object_store is the right shape for
//! hekate's needs (S3 + local + Azure + GCS) at ~3× lower compile cost,
//! and we already commit to local-FS-only for the §13 single-host
//! deployment shape. The trait keeps the door open without burning
//! 5 MB of compile time we don't need today.

use async_trait::async_trait;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

/// Errors a `BlobStore` can return. Mapped into HTTP responses by the
/// route layer (`routes::attachments`); other callers (cleanup worker)
/// just log them.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("blob not found: {0}")]
    NotFound(String),
    #[error("blob io: {0}")]
    Io(#[from] io::Error),
    #[error("blob unsupported: {0}")]
    Unsupported(String),
}

pub type BlobResult<T> = Result<T, BlobError>;

/// Abstract blob backend. All operations are keyed by an opaque
/// `storage_key` (typically `<user_id>/<attachment_id>`).
///
/// Operations:
///
/// - `append` — appends bytes to the blob at `storage_key`, growing it.
///   Used by tus PATCH chunked uploads. Idempotency is the caller's
///   responsibility (tus enforces strict offset matching).
/// - `len` — current ciphertext length (for tus HEAD `Upload-Offset`).
/// - `read_range` — read a contiguous byte range. M2.24 always reads
///   from offset 0 to end (no Range support); preserved for future use.
/// - `read_full` — convenience: read the entire blob.
/// - `delete` — remove the blob. Called from the cleanup worker after
///   the row is gone.
#[async_trait]
pub trait BlobStore: Send + Sync + 'static {
    async fn append(&self, storage_key: &str, bytes: &[u8]) -> BlobResult<()>;
    async fn len(&self, storage_key: &str) -> BlobResult<u64>;
    async fn read_range(&self, storage_key: &str, offset: u64, len: u64) -> BlobResult<Vec<u8>>;
    async fn read_full(&self, storage_key: &str) -> BlobResult<Vec<u8>> {
        let n = self.len(storage_key).await?;
        self.read_range(storage_key, 0, n).await
    }
    async fn delete(&self, storage_key: &str) -> BlobResult<()>;
    async fn exists(&self, storage_key: &str) -> BlobResult<bool>;
}

/// Local-filesystem blob store. Files live under
/// `<root>/<storage_key>`; subdirectories are created on first write.
///
/// Concurrent PATCHes against the same `storage_key` would interleave
/// bytes — the tus handler holds a row lock on `attachment_uploads`
/// before calling `append` so two PATCHes for the same upload serialize.
pub struct LocalFsBlobStore {
    root: PathBuf,
}

impl LocalFsBlobStore {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn full_path(&self, storage_key: &str) -> BlobResult<PathBuf> {
        // Defense against `..` traversal: refuse any storage_key that
        // contains a path separator other than `/`, or any `.` segment.
        // We expect `<user_id>/<attachment_id>` where each segment is a
        // UUIDv7 — alphanumerics + dashes only.
        for segment in storage_key.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(BlobError::Unsupported(format!(
                    "invalid storage_key segment {segment:?}"
                )));
            }
            if segment
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            {
                return Err(BlobError::Unsupported(format!(
                    "storage_key segment must be [a-zA-Z0-9_-]+; got {segment:?}"
                )));
            }
        }
        Ok(self.root.join(storage_key))
    }
}

#[async_trait]
impl BlobStore for LocalFsBlobStore {
    async fn append(&self, storage_key: &str, bytes: &[u8]) -> BlobResult<()> {
        let path = self.full_path(storage_key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // OpenOptions::append=true is atomic per write() on POSIX.
        // Concurrent appenders would interleave bytes; the route layer
        // serializes via the upload row's `bytes_received` check.
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        use tokio::io::AsyncWriteExt;
        file.write_all(bytes).await?;
        file.flush().await?;
        Ok(())
    }

    async fn len(&self, storage_key: &str) -> BlobResult<u64> {
        let path = self.full_path(storage_key)?;
        match tokio::fs::metadata(&path).await {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(BlobError::Io(e)),
        }
    }

    async fn read_range(&self, storage_key: &str, offset: u64, len: u64) -> BlobResult<Vec<u8>> {
        let path = self.full_path(storage_key)?;
        use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
        let mut file = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(BlobError::NotFound(storage_key.into()));
            }
            Err(e) => return Err(BlobError::Io(e)),
        };
        if offset > 0 {
            file.seek(SeekFrom::Start(offset)).await?;
        }
        let mut buf = vec![0u8; len as usize];
        file.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn delete(&self, storage_key: &str) -> BlobResult<()> {
        let path = self.full_path(storage_key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(BlobError::Io(e)),
        }
    }

    async fn exists(&self, storage_key: &str) -> BlobResult<bool> {
        let path = self.full_path(storage_key)?;
        match tokio::fs::metadata(&path).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(BlobError::Io(e)),
        }
    }
}

/// Type alias used by `AppState` and tus handlers — clones cheaply.
pub type DynBlobStore = Arc<dyn BlobStore>;

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempdir_lite::TempDir {
        tempdir_lite::TempDir::new("hekate-blob-test").expect("tempdir")
    }

    #[tokio::test]
    async fn append_then_read_round_trips() {
        let dir = tmp();
        let s = LocalFsBlobStore::new(dir.path()).unwrap();
        s.append("u1/a1", b"hello ").await.unwrap();
        s.append("u1/a1", b"world").await.unwrap();
        assert_eq!(s.len("u1/a1").await.unwrap(), 11);
        let body = s.read_full("u1/a1").await.unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn missing_blob_len_zero() {
        let dir = tmp();
        let s = LocalFsBlobStore::new(dir.path()).unwrap();
        assert_eq!(s.len("u/missing").await.unwrap(), 0);
        assert!(!s.exists("u/missing").await.unwrap());
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let dir = tmp();
        let s = LocalFsBlobStore::new(dir.path()).unwrap();
        s.append("u1/a1", b"x").await.unwrap();
        s.delete("u1/a1").await.unwrap();
        s.delete("u1/a1").await.unwrap();
        assert!(!s.exists("u1/a1").await.unwrap());
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let dir = tmp();
        let s = LocalFsBlobStore::new(dir.path()).unwrap();
        assert!(s.append("../escape", b"x").await.is_err());
        assert!(s.append("u1/../escape", b"x").await.is_err());
        assert!(s.append("./oops", b"x").await.is_err());
        assert!(s.append("u1/a$b", b"x").await.is_err());
    }

    #[tokio::test]
    async fn read_range_offset() {
        let dir = tmp();
        let s = LocalFsBlobStore::new(dir.path()).unwrap();
        s.append("u/a", b"abcdef").await.unwrap();
        let mid = s.read_range("u/a", 2, 3).await.unwrap();
        assert_eq!(mid, b"cde");
    }
}

// Tiny in-tree tempdir helper so tests don't pull in a full crate.
// The dev image won't add `tempfile` for one test file.
#[cfg(test)]
mod tempdir_lite {
    use std::path::{Path, PathBuf};

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new(prefix: &str) -> std::io::Result<Self> {
            use rand::Rng;
            let suffix: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(12)
                .map(char::from)
                .collect();
            let mut path = std::env::temp_dir();
            path.push(format!("{prefix}-{suffix}"));
            std::fs::create_dir_all(&path)?;
            Ok(Self { path })
        }
        pub fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
