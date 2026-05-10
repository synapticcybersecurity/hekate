//! In-process push fanout. A single tokio broadcast channel; SSE
//! subscribers filter by user_id.
//!
//! Multi-replica deployments will swap this for Redis Streams pub/sub.
//! Channel capacity 1024 is enough that even a slow subscriber lagging
//! by a second or two won't drop events on a personal-vault workload.

use serde::Serialize;
use std::sync::Arc;
use tokio::sync::broadcast;

pub const CHANNEL_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushKind {
    CipherChanged,
    CipherDeleted,
    CipherTombstoned,
    FolderChanged,
    FolderTombstoned,
    /// (M2.24) Attachment finalize / delete / tombstone. Carries the
    /// attachment id; the cipher's `revision_date` is also bumped so a
    /// `cipher.changed` follows.
    AttachmentChanged,
    AttachmentTombstoned,
    /// (M2.25) Send create / update / disable / enable / public-access
    /// counter bump. Carries the send id.
    SendChanged,
    SendTombstoned,
}

impl PushKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PushKind::CipherChanged => "cipher.changed",
            PushKind::CipherDeleted => "cipher.deleted",
            PushKind::CipherTombstoned => "cipher.tombstoned",
            PushKind::FolderChanged => "folder.changed",
            PushKind::FolderTombstoned => "folder.tombstoned",
            PushKind::AttachmentChanged => "attachment.changed",
            PushKind::AttachmentTombstoned => "attachment.tombstoned",
            PushKind::SendChanged => "send.changed",
            PushKind::SendTombstoned => "send.tombstoned",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PushEvent {
    pub user_id: String,
    pub kind: PushKind,
    pub id: String,
    pub revision: String,
}

#[derive(Clone)]
pub struct PushBus(Arc<broadcast::Sender<PushEvent>>);

impl PushBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self(Arc::new(tx))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PushEvent> {
        self.0.subscribe()
    }

    /// Best-effort send. Errors (no subscribers, channel full) are intentional.
    pub fn publish(&self, event: PushEvent) {
        let _ = self.0.send(event);
    }
}

impl Default for PushBus {
    fn default() -> Self {
        Self::new()
    }
}
