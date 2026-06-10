use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::header::Security;
use super::kdf::{kdf12, kdf16};

/// Maximum plaintext per body record (matching upstream 16 KiB - 16 tag).
const MAX_PLAINTEXT: usize = 16384 - 16;

/// Body keys/IVs derived from the per-connection req_key and req_iv.
struct DerivedKeys {
    write_key: Vec<u8>,
    write_iv: [u8; 12],
    read_key: Vec<u8>,
    read_iv: [u8; 12],
}

fn derive_keys(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16]) -> DerivedKeys {
    let mut key_iv = [0u8; 32];
    key_iv[..16].copy_from_slice(req_key);
    key_iv[16..].copy_from_slice(req_iv);

    let (write_key, write_iv) = match security {
        Security::Aes128Gcm => {
            let k = kdf16(&key_iv, &[b"VMess Body AEAD Key"]);
            let iv = kdf12(&key_iv, &[b"VMess Body AEAD IV"]);
            (k.to_vec(), iv)
        }
        Security::ChaCha20Poly1305 => {
            let mut hasher = Md5::new();
            hasher.update(req_key);
            let md5_1: [u8; 16] = hasher.finalize().into();
            let mut hasher2 = Md5::new();
            hasher2.update(md5_1);
            let md5_2: [u8; 16] = hasher2.finalize().into();
            let mut k = Vec::with_capacity(32);
            k.extend_from_slice(&md5_1);
            k.extend_from_slice(&md5_2);
            let iv = kdf12(&key_iv, &[b"VMess Body AEAD IV"]);
            (k, iv)
        }
        Security::None => (Vec::new(), [0u8; 12]),
    };

    // Response keys: swap req_key/req_iv
    let mut resp_key_iv = [0u8; 32];
    resp_key_iv[..16].copy_from_slice(req_iv);
    resp_key_iv[16..].copy_from_slice(req_key);

    let (read_key, read_iv) = match security {
        Security::Aes128Gcm => {
            let k = kdf16(&resp_key_iv, &[b"VMess Body AEAD Key"]);
            let iv = kdf12(&resp_key_iv, &[b"VMess Body AEAD IV"]);
            (k.to_vec(), iv)
        }
        Security::ChaCha20Poly1305 => {
            let mut hasher = Md5::new();
            hasher.update(req_iv);
            let md5_1: [u8; 16] = hasher.finalize().into();
            let mut hasher2 = Md5::new();
            hasher2.update(md5_1);
            let md5_2: [u8; 16] = hasher2.finalize().into();
            let mut k = Vec::with_capacity(32);
            k.extend_from_slice(&md5_1);
            k.extend_from_slice(&md5_2);
            let iv = kdf12(&resp_key_iv, &[b"VMess Body AEAD IV"]);
            (k, iv)
        }
        Security::None => (Vec::new(), [0u8; 12]),
    };

    DerivedKeys {
        write_key,
        write_iv,
        read_key,
        read_iv,
    }
}

/// One direction's AEAD state. The cipher object (the expanded key schedule)
/// is built once per connection — only the nonce changes per record.
#[derive(Clone)]
enum RecordCipher {
    None,
    /// Boxed: the AES key schedule is ~10× the size of the other variants.
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl RecordCipher {
    fn new(security: Security, key: &[u8]) -> Self {
        match security {
            Security::None => Self::None,
            Security::Aes128Gcm => Self::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(key).expect("derived AES-128 key is 16 bytes"),
            )),
            Security::ChaCha20Poly1305 => Self::ChaCha20Poly1305(Box::new(
                ChaCha20Poly1305::new_from_slice(key).expect("derived ChaCha20 key is 32 bytes"),
            )),
        }
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::None => Err(std::io::Error::other("seal called with Security::None")),
            Self::Aes128Gcm(c) => c
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|e| std::io::Error::other(format!("aes-gcm encrypt: {e}"))),
            Self::ChaCha20Poly1305(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|e| std::io::Error::other(format!("chacha encrypt: {e}"))),
        }
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::None => Err(std::io::Error::other("open called with Security::None")),
            Self::Aes128Gcm(c) => c
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| std::io::Error::other(format!("aes-gcm decrypt: {e}"))),
            Self::ChaCha20Poly1305(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| std::io::Error::other(format!("chacha decrypt: {e}"))),
        }
    }
}

/// Per-connection body cipher state for both directions.
pub struct BodyCipher {
    write: RecordCipher,
    write_iv: [u8; 12],
    read: RecordCipher,
    read_iv: [u8; 12],
    write_counter: u16,
    read_counter: u16,
}

impl BodyCipher {
    pub fn new(security: Security, req_key: &[u8; 16], req_iv: &[u8; 16], resp_v: u8) -> Self {
        // XOR of resp_v into the response IV seed is handled upstream of the
        // body layer; the parameter is kept for signature stability.
        let _ = resp_v;
        let keys = derive_keys(security, req_key, req_iv);

        Self {
            write: RecordCipher::new(security, &keys.write_key),
            write_iv: keys.write_iv,
            read: RecordCipher::new(security, &keys.read_key),
            read_iv: keys.read_iv,
            write_counter: 0,
            read_counter: 0,
        }
    }

    /// Test hook: make the read direction decrypt what the write direction
    /// encrypts (real connections derive read keys from swapped req material).
    #[cfg(test)]
    fn mirror_write_to_read(&mut self) {
        self.read = self.write.clone();
        self.read_iv = self.write_iv;
        self.read_counter = self.write_counter;
    }

    fn write_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.write_iv;
        let counter_be = self.write_counter.to_be_bytes();
        nonce[0] ^= counter_be[0];
        nonce[1] ^= counter_be[1];
        self.write_counter = self.write_counter.wrapping_add(1);
        nonce
    }

    fn read_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.read_iv;
        let counter_be = self.read_counter.to_be_bytes();
        nonce[0] ^= counter_be[0];
        nonce[1] ^= counter_be[1];
        self.read_counter = self.read_counter.wrapping_add(1);
        nonce
    }

    /// Encrypt and write one body record: [len(2 BE)][ciphertext + tag(16)].
    /// Length includes the tag.
    pub async fn write_record<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        plaintext: &[u8],
    ) -> std::io::Result<()> {
        if matches!(self.write, RecordCipher::None) {
            writer.write_all(plaintext).await?;
            return writer.flush().await;
        }

        let nonce = self.write_nonce();
        let ct = self.write.seal(&nonce, plaintext)?;
        let len = ct.len() as u16;
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&ct).await?;
        writer.flush().await
    }

    /// Read and decrypt one body record.
    pub async fn read_record<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<Vec<u8>> {
        if matches!(self.read, RecordCipher::None) {
            let mut buf = vec![0u8; 4096];
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            buf.truncate(n);
            return Ok(buf);
        }

        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let ct_len = u16::from_be_bytes(len_buf) as usize;
        if ct_len == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct).await?;
        let nonce = self.read_nonce();
        self.read.open(&nonce, &ct)
    }

    pub fn max_plaintext() -> usize {
        MAX_PLAINTEXT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> ([u8; 16], [u8; 16]) {
        let req_key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let req_iv = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ];
        (req_key, req_iv)
    }

    #[tokio::test]
    async fn aes_128_gcm_record_round_trip() {
        let (req_key, req_iv) = test_keys();
        let mut writer_cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        let plaintext = b"hello vmess aes-128-gcm body";

        let mut wire = Vec::new();
        writer_cipher
            .write_record(&mut wire, plaintext)
            .await
            .unwrap();

        // Wire must be: 2-byte length + ciphertext(plaintext_len + 16 tag)
        let expected_ct_len = plaintext.len() + 16;
        let wire_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        assert_eq!(
            wire_len, expected_ct_len,
            "record length must include the 16-byte tag"
        );
        assert_eq!(wire.len(), 2 + expected_ct_len);

        // Now read it back — use WRITE keys since we're decrypting what we wrote
        // (read_cipher uses response keys derived from swapped req_iv/req_key)
        // For self-round-trip, we need a cipher with matching keys.
        let mut read_cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        read_cipher.mirror_write_to_read();

        let mut cursor = std::io::Cursor::new(wire);
        let decrypted = read_cipher.read_record(&mut cursor).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn chacha20_poly1305_record_round_trip() {
        let (req_key, req_iv) = test_keys();
        let mut writer_cipher =
            BodyCipher::new(Security::ChaCha20Poly1305, &req_key, &req_iv, 0x42);
        let plaintext = b"hello vmess chacha20 body";

        let mut wire = Vec::new();
        writer_cipher
            .write_record(&mut wire, plaintext)
            .await
            .unwrap();

        let expected_ct_len = plaintext.len() + 16;
        let wire_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        assert_eq!(wire_len, expected_ct_len);

        let mut read_cipher = BodyCipher::new(Security::ChaCha20Poly1305, &req_key, &req_iv, 0x42);
        read_cipher.mirror_write_to_read();

        let mut cursor = std::io::Cursor::new(wire);
        let decrypted = read_cipher.read_record(&mut cursor).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn none_is_passthrough() {
        let (req_key, req_iv) = test_keys();
        let mut cipher = BodyCipher::new(Security::None, &req_key, &req_iv, 0x42);
        let plaintext = b"raw bytes no framing";

        let mut wire = Vec::new();
        cipher.write_record(&mut wire, plaintext).await.unwrap();
        assert_eq!(wire, plaintext, "security:none must not add framing");
    }

    #[tokio::test]
    async fn nonce_counter_increments_per_record() {
        let (req_key, req_iv) = test_keys();
        let mut cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        let data = b"x";

        let mut wire1 = Vec::new();
        cipher.write_record(&mut wire1, data).await.unwrap();
        let mut wire2 = Vec::new();
        cipher.write_record(&mut wire2, data).await.unwrap();
        let mut wire3 = Vec::new();
        cipher.write_record(&mut wire3, data).await.unwrap();

        // Same plaintext with different nonces must produce different ciphertext
        assert_ne!(wire1, wire2);
        assert_ne!(wire2, wire3);
        assert_ne!(wire1, wire3);
    }

    #[test]
    fn chacha_key_uses_md5_cascade_not_kdf() {
        let (req_key, req_iv) = test_keys();
        let keys = derive_keys(Security::ChaCha20Poly1305, &req_key, &req_iv);
        // ChaCha20 body_key = MD5(req_key) || MD5(MD5(req_key)) — 32 bytes
        assert_eq!(
            keys.write_key.len(),
            32,
            "chacha key must be 32 bytes (double MD5)"
        );

        let mut hasher = Md5::new();
        hasher.update(req_key);
        let md5_1: [u8; 16] = hasher.finalize().into();
        let mut hasher2 = Md5::new();
        hasher2.update(md5_1);
        let md5_2: [u8; 16] = hasher2.finalize().into();

        assert_eq!(&keys.write_key[..16], &md5_1);
        assert_eq!(&keys.write_key[16..], &md5_2);
    }

    #[test]
    fn aes_key_uses_kdf_not_md5() {
        let (req_key, req_iv) = test_keys();
        let keys = derive_keys(Security::Aes128Gcm, &req_key, &req_iv);
        assert_eq!(keys.write_key.len(), 16, "aes key must be 16 bytes (KDF)");
        // Verify it matches the KDF derivation
        let mut key_iv = [0u8; 32];
        key_iv[..16].copy_from_slice(&req_key);
        key_iv[16..].copy_from_slice(&req_iv);
        let expected = kdf16(&key_iv, &[b"VMess Body AEAD Key"]);
        assert_eq!(keys.write_key.as_slice(), &expected);
    }

    #[tokio::test]
    async fn record_length_includes_tag() {
        let (req_key, req_iv) = test_keys();
        let mut cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x42);
        let plaintext = vec![0xAB; 100];

        let mut wire = Vec::new();
        cipher.write_record(&mut wire, &plaintext).await.unwrap();

        let wire_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        // upstream: len = plaintext_len + 16 (tag), NOT just plaintext_len
        assert_eq!(
            wire_len,
            100 + 16,
            "record length must be plaintext + 16 (tag)"
        );
    }
}
