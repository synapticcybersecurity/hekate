use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// `host:port` to bind. Default `0.0.0.0:8080`.
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Connection URL. `sqlite://path` or `postgres://user:pw@host/db`.
    /// Default: `sqlite:///data/hekate.sqlite?mode=rwc`.
    #[serde(default = "default_database_url")]
    pub database_url: String,

    /// Server-local pepper used to derive deterministic-looking fake KDF
    /// salts for unknown emails on prelogin (so existence isn't trivially
    /// leakable). 16+ bytes recommended. Auto-generated on first run if
    /// unset.
    #[serde(default = "default_fake_salt_pepper", with = "pepper_serde")]
    pub fake_salt_pepper: Vec<u8>,

    /// WebAuthn Relying Party ID (M2.23). Must match the eTLD+1 of the
    /// origin the browser is on (or `localhost` for dev). Defaults to
    /// `hekate.localhost` so `make up` Just Works in dev. Self-host
    /// deployments MUST set this to their domain (e.g. `vault.example.com`).
    #[serde(default = "default_webauthn_rp_id")]
    pub webauthn_rp_id: String,

    /// WebAuthn origin URL — `<scheme>://<host>[:<port>]` exactly as
    /// the browser sees it. Defaults to `http://hekate.localhost`. Must
    /// be HTTPS in production except when host is `localhost` or
    /// `*.localhost` (browsers treat those as Potentially Trustworthy).
    #[serde(default = "default_webauthn_rp_origin")]
    pub webauthn_rp_origin: String,

    /// Filesystem root for the local-FS attachment blob store (M2.24).
    /// Created on bootstrap if missing. Single-host self-hosters can leave
    /// this on the default; cloud deployments will swap to S3 in M2.24a
    /// via a future `attachments_backend = "s3" | "fs"` knob.
    #[serde(default = "default_attachments_dir")]
    pub attachments_dir: String,

    /// Per-attachment ciphertext byte cap. Default 100 MiB. Plaintext
    /// is bounded by `ciphertext_size_for(plaintext)` plus chunk-tag
    /// overhead (~0.0015%). Refused at tus creation if exceeded.
    #[serde(default = "default_max_attachment_bytes")]
    pub max_attachment_bytes: u64,

    /// Per-account ciphertext byte cap across all completed attachments.
    /// Default 10 GiB. Cheap to compute (`SUM(size_ct)` on an indexed
    /// status=1 partition).
    #[serde(default = "default_max_account_bytes")]
    pub max_account_attachment_bytes: u64,

    /// Per-cipher ciphertext byte cap. Default 1 GiB. Mostly a UI sanity
    /// guard; account cap is the real backstop.
    #[serde(default = "default_max_cipher_bytes")]
    pub max_cipher_attachment_bytes: u64,

    /// Filesystem root for the static SPA assets (`clients/web/dist`).
    /// When `None` or the directory is missing, `/web/*` and `/send/*`
    /// fall back to a tiny built-in HTML page that explains the web
    /// vault hasn't been built — keeps existing share URLs functional
    /// in dev environments where the SPA hasn't been compiled. In the
    /// production Dockerfile this is set to `/app/web-dist`.
    #[serde(default = "default_web_dir")]
    pub web_dir: Option<String>,

    /// Allow webhook destinations that point at private / loopback /
    /// link-local / multicast IPs, or that use plain `http://`. Default
    /// `false` — the production posture is to block SSRF vectors
    /// (cloud metadata, internal admin surfaces, RFC1918, …) and force
    /// HTTPS so the HMAC signature isn't trivially trafficable in
    /// flight. Set to `true` in dev compose to point webhooks at a
    /// localhost test receiver.
    #[serde(default)]
    pub webhooks_allow_unsafe_destinations: bool,

    /// Origin allowlist for cross-origin browser callers. Each entry is
    /// a full origin string (e.g. `https://vault.example.com`,
    /// `http://localhost:5173`). Same-origin requests don't go through
    /// CORS, so default deployments where the SPA + API share an
    /// origin can leave this empty. Populate it for split-host
    /// deployments (SPA on a CDN, API on a separate hostname) or to
    /// expose the API to other browser-based first-party tooling.
    ///
    /// Comparison is exact-match on the full origin (scheme + host +
    /// port). Wildcards aren't supported — explicit allowlists are
    /// the security-best-practice posture and what auditors expect.
    /// Browser extensions don't use this (they have their own
    /// cross-origin grant via manifest `host_permissions`); if your
    /// extension is cross-origin it's already covered there.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,

    /// Trust the leftmost entry of `X-Forwarded-For` (or
    /// `Forwarded: for=`) as the client IP for rate-limiting purposes.
    /// Default `false` — only set this to `true` when hekate-server sits
    /// behind a reverse proxy you control that strips/rewrites these
    /// headers (Traefik, nginx, Caddy, ALB, …). Trusting them on a
    /// directly-exposed deployment lets any client spoof their IP and
    /// bypass per-IP rate limits.
    #[serde(default)]
    pub trust_proxy_headers: bool,
}

mod pepper_serde {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Used when the config is round-tripped (e.g. logging or future config
    /// dump). Not currently called but kept symmetric with `deserialize`.
    #[allow(dead_code)]
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD_NO_PAD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD_NO_PAD.decode(&s).map_err(serde::de::Error::custom)
    }
}

fn default_listen() -> String {
    "0.0.0.0:8080".into()
}

fn default_database_url() -> String {
    "sqlite:///data/hekate.sqlite?mode=rwc".into()
}

fn default_webauthn_rp_id() -> String {
    "hekate.localhost".into()
}

fn default_webauthn_rp_origin() -> String {
    "http://hekate.localhost".into()
}

fn default_attachments_dir() -> String {
    "/data/attachments".into()
}

fn default_max_attachment_bytes() -> u64 {
    100 * 1024 * 1024
}

fn default_max_account_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}

fn default_max_cipher_bytes() -> u64 {
    1024 * 1024 * 1024
}

fn default_web_dir() -> Option<String> {
    None
}

fn default_fake_salt_pepper() -> Vec<u8> {
    use rand::RngCore;
    // Generated once per process if not configured. For deterministic
    // responses across restarts, set `HEKATE_FAKE_SALT_PEPPER` to a base64
    // value via env or hekate.toml.
    let mut p = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut p);
    p
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            database_url: default_database_url(),
            fake_salt_pepper: default_fake_salt_pepper(),
            webauthn_rp_id: default_webauthn_rp_id(),
            webauthn_rp_origin: default_webauthn_rp_origin(),
            attachments_dir: default_attachments_dir(),
            max_attachment_bytes: default_max_attachment_bytes(),
            max_account_attachment_bytes: default_max_account_bytes(),
            max_cipher_attachment_bytes: default_max_cipher_bytes(),
            web_dir: default_web_dir(),
            webhooks_allow_unsafe_destinations: false,
            cors_allowed_origins: Vec::new(),
            trust_proxy_headers: false,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        Figment::new()
            .merge(Toml::file("hekate.toml"))
            .merge(Env::prefixed("HEKATE_"))
            .extract()
            .map_err(Into::into)
    }

    /// Database URL with any password component stripped, for log lines.
    pub fn database_url_redacted(&self) -> String {
        match url::Url::parse(&self.database_url) {
            Ok(mut u) => {
                if u.password().is_some() {
                    let _ = u.set_password(Some("REDACTED"));
                }
                u.to_string()
            }
            Err(_) => self.database_url.clone(),
        }
    }
}
