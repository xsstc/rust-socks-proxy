use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt::{self, Formatter, Debug};
use std::error::Error;

// AES-256-CBC 类型别名
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// IV（初始化向量）的长度
const IV_LEN: usize = 16;

// 自定义错误类型
#[derive(Debug)]
struct CryptoError(String);

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for CryptoError {}

// 加密函数，返回 Vec<u8>
pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if key.len() != 32 {
        return Err(Box::new(CryptoError("Key must be 32 bytes".into())));
    }

    // 生成随机的 IV
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);

    // 创建加密器
    let cipher = Aes256Cbc::new_from_slices(key, &iv)
        .map_err(|e| Box::new(CryptoError(format!("Error creating cipher: {}", e))) as Box<dyn Error>)?;

    // 加密数据
    let ciphertext = cipher.encrypt_vec(data);

    // 将 IV 和加密数据连接起来
    let mut encrypted_data = Vec::with_capacity(iv.len() + ciphertext.len());
    encrypted_data.extend_from_slice(&iv);
    encrypted_data.extend_from_slice(&ciphertext);

    Ok(encrypted_data)
}

// 解密函数，返回 Vec<u8>
pub fn decrypt(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if key.len() != 32 {
        return Err(Box::new(CryptoError("Key must be 32 bytes".into())));
    }

    if encrypted_data.len() < IV_LEN {
        return Err(Box::new(CryptoError("Invalid encrypted data".into())));
    }

    // 分离 IV 和加密数据
    let (iv, ciphertext) = encrypted_data.split_at(IV_LEN);

    // 创建解密器
    let cipher = Aes256Cbc::new_from_slices(key, iv)
        .map_err(|e| Box::new(CryptoError(format!("Error creating cipher: {}", e))) as Box<dyn Error>)?;

    // 解密数据
    cipher.decrypt_vec(ciphertext)
        .map_err(|e| Box::new(CryptoError(format!("Error decrypting data: {}", e))) as Box<dyn Error>)
}
