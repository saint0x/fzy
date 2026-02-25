use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use capabilities::{Capability, CapabilitySet};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct ServerHardeningDefaults {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_connections: usize,
    pub request_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub parse_timeout_ms: u64,
}

impl Default for ServerHardeningDefaults {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_body_bytes: 1024 * 1024,
            max_connections: 1024,
            request_timeout_ms: 5_000,
            idle_timeout_ms: 15_000,
            parse_timeout_ms: 1_000,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    bytes: Vec<u8>,
}

impl Secret {
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: value.as_ref().to_vec(),
        }
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn redacted(&self) -> &'static str {
        "[redacted]"
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("value", &"[redacted]")
            .finish()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // Safety: secure zeroing write for key material.
            unsafe {
                std::ptr::write_volatile(byte as *mut u8, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegedOperation {
    NetworkBind,
    FileWrite,
    ProcessSpawn,
}

impl PrivilegedOperation {
    pub fn required_capability(&self) -> Capability {
        match self {
            Self::NetworkBind => Capability::Network,
            Self::FileWrite => Capability::FileSystem,
            Self::ProcessSpawn => Capability::Process,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityAudit {
    pub operation: PrivilegedOperation,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum AuditSink {
    Memory,
    File(PathBuf),
}

#[derive(Debug, Default, Clone)]
pub struct AuditLogger {
    sink: Option<AuditSink>,
    entries: Vec<CapabilityAudit>,
}

impl AuditLogger {
    pub fn with_sink(sink: AuditSink) -> Self {
        Self {
            sink: Some(sink),
            entries: Vec::new(),
        }
    }

    pub fn record(&mut self, audit: CapabilityAudit) {
        if let Some(AuditSink::File(path)) = &self.sink {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let line = serde_json::to_string(&audit).unwrap_or_else(|_| "{}".to_string());
                let _ = writeln!(file, "{}", line);
            }
        }
        self.entries.push(audit);
    }

    pub fn entries(&self) -> &[CapabilityAudit] {
        &self.entries
    }
}

pub fn audit_privileged_operation(
    caps: &CapabilitySet,
    operation: PrivilegedOperation,
    reason: impl Into<String>,
) -> CapabilityAudit {
    let required = operation.required_capability();
    CapabilityAudit {
        operation,
        allowed: caps.contains(required),
        reason: reason.into(),
    }
}

pub fn audit_privileged_operation_with_sink(
    caps: &CapabilitySet,
    operation: PrivilegedOperation,
    reason: impl Into<String>,
    sink: &mut AuditLogger,
) -> CapabilityAudit {
    let audit = audit_privileged_operation(caps, operation, reason);
    sink.record(audit.clone());
    audit
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn sha512(input: &[u8]) -> [u8; 64] {
    let digest = Sha512::digest(input);
    let mut out = [0_u8; 64];
    out.copy_from_slice(&digest);
    out
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    EncryptFailed,
    DecryptFailed,
}

pub fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| CryptoError::EncryptFailed)
}

pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::DecryptFailed)
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    capacity: u64,
    refill_per_sec: u64,
    tokens: u64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(capacity: u64, refill_per_sec: u64) -> Self {
        Self {
            capacity: capacity.max(1),
            refill_per_sec: refill_per_sec.max(1),
            tokens: capacity.max(1),
            last_refill: Instant::now(),
        }
    }

    pub fn allow(&mut self, cost: u64) -> bool {
        self.refill();
        let cost = cost.max(1);
        if self.tokens < cost {
            return false;
        }
        self.tokens -= cost;
        true
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed();
        if elapsed < Duration::from_millis(100) {
            return;
        }
        let add = (elapsed.as_secs_f64() * self.refill_per_sec as f64) as u64;
        self.tokens = (self.tokens + add).min(self.capacity);
        self.last_refill = Instant::now();
    }
}

#[derive(Debug, Clone)]
pub struct RequestThrottler {
    limiter: RateLimiter,
}

impl RequestThrottler {
    pub fn new(max_rps: u64, burst: u64) -> Self {
        Self {
            limiter: RateLimiter::new(burst, max_rps),
        }
    }

    pub fn allow_request(&mut self) -> bool {
        self.limiter.allow(1)
    }
}

#[cfg(test)]
mod tests {
    use capabilities::{Capability, CapabilitySet};

    use super::{
        aes_gcm_decrypt, aes_gcm_encrypt, audit_privileged_operation_with_sink, hmac_sha256,
        sha256, sha512, AuditLogger, AuditSink, PrivilegedOperation, RequestThrottler, Secret,
    };

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret::new("token");
        let printed = format!("{:?}", secret);
        assert!(printed.contains("[redacted]"));
        assert!(!printed.contains("token"));
    }

    #[test]
    fn cryptographic_primitives_work() {
        assert_eq!(sha256(b"abc").len(), 32);
        assert_eq!(sha512(b"abc").len(), 64);
        assert_eq!(hmac_sha256(b"k", b"m").len(), 32);

        let key = [7_u8; 32];
        let nonce = [3_u8; 12];
        let cipher = aes_gcm_encrypt(&key, &nonce, b"hello").expect("encrypt");
        let plain = aes_gcm_decrypt(&key, &nonce, &cipher).expect("decrypt");
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn request_throttler_applies_rate_limit() {
        let mut throttler = RequestThrottler::new(1, 2);
        assert!(throttler.allow_request());
        assert!(throttler.allow_request());
        assert!(!throttler.allow_request());
    }

    #[test]
    fn persistent_audit_sink_records_entries() {
        let path = std::env::temp_dir().join("fozzy-audit.log");
        let mut logger = AuditLogger::with_sink(AuditSink::File(path.clone()));
        let mut caps = CapabilitySet::default();
        caps.insert(Capability::Network);
        let audit = audit_privileged_operation_with_sink(
            &caps,
            PrivilegedOperation::NetworkBind,
            "boot",
            &mut logger,
        );
        assert!(audit.allowed);
        assert!(!logger.entries().is_empty());
        let text = std::fs::read_to_string(&path).expect("audit file");
        assert!(text.contains("NetworkBind"));
        let _ = std::fs::remove_file(path);
    }
}
