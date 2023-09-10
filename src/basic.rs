use rand::{thread_rng, Rng};

use sha1_smol::Sha1;

use base64ct::{
    Base64,
    Encoding
};

pub struct BasicGenerator;

impl BasicGenerator {
    pub const CLIENT_ID: &str = "MsOIJ39Q28";
    pub const CLIENT_SECRET: &str = "PTDc3H8a)Vi=UYap";
    pub const CHARSET: &[u8] = b"ABCDEF1234567890";

    /// Generate a new Basic Authorization token for iFunny.
    /// 
    /// ## Examples
    /// ```
    /// use lib::basic::BasicGenerator;
    /// let basic = BasicGenerator::generate();
    /// ```
    pub fn generate() -> String {
        let mut rng = thread_rng();
        let hex: String = (0..72).map(|_|{
            unsafe {
                char::from(*Self::CHARSET.get_unchecked(rng.gen_range(0..16)))
            }
        }).collect();
        let hex_id = format!("{}_{}", &hex, BasicGenerator::CLIENT_ID);
        let decoded_hash: String = format!("{}:{}:{}", &hex, BasicGenerator::CLIENT_ID, Self::CLIENT_SECRET);
        let mut encoded_hash = Sha1::new();
        encoded_hash.update(decoded_hash.as_bytes());
        let encoded_hash: String = encoded_hash.digest().to_string();
        let auth_token = format!("{}:{}", hex_id, encoded_hash);
        Base64::encode_string(auth_token.as_bytes())
    }
}