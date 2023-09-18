use uuid::Uuid;

use base64ct::{Base64, Encoding};
use sha1_smol::Sha1;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct BasicToken(String);

impl std::fmt::Display for BasicToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BasicTokenLength {
    Length112 = 112,
    Length156 = 156,
}

impl BasicToken {
    pub const CLIENT_ID: &str = "MsOIJ39Q28";
    pub const CLIENT_SECRET: &str = "PTDc3H8a)Vi=UYap";

    /// Create a new Basic Authorization token for iFunny with the given client_id and client_secret and length
    ///
    /// # Arguments
    /// * `client_id` - The client_id for iFunny
    /// * `client_secret` - The client_secret for iFunny
    /// * `length` - The length of the token (112 or 156)
    ///
    /// # Returns
    /// * BasicToken
    ///
    /// # Examples
    /// ```
    /// use ifunny_auth::basic::{BasicToken, BasicTokenLength};
    ///
    /// let basic: BasicToken = BasicToken::new("MsOIJ39Q28", "PTDc3H8a)Vi=UYap", BasicTokenLength::Length112);
    /// assert_eq!(basic.len(), 112);
    /// ```
    pub fn new(client_id: &str, client_secret: &str, length: BasicTokenLength) -> Self {
        let uuid = Uuid::new_v4().simple();

        let hex = match length {
            BasicTokenLength::Length112 => uuid.to_string().to_uppercase(),
            BasicTokenLength::Length156 => {
                let mut hasher = Sha256::new();
                hasher.update(uuid.to_string());

                let result = hasher.finalize();
                format!("{:x}", result)
            }
        }
        .to_uppercase();

        let a = format!("{}_{}:", hex, client_id);
        let b = format!("{}:{}:{}", hex, client_id, client_secret);

        let c: String = {
            let mut hasher = Sha1::new();
            hasher.update(b.as_bytes());
            format!("{}", hasher.digest().to_string())
        };

        let decoded_hash = format!("{}{}", a, c);

        Self(Base64::encode_string(decoded_hash.as_bytes()))
    }

    /// Generate a new Basic Authorization token for iFunny using the default values for client_id and client_secret and length
    ///
    /// # Examples
    /// ```
    /// use ifunny_auth::basic::BasicToken;
    /// let basic: BasicToken = BasicToken::generate();
    /// ```
    pub fn generate() -> Self {
        Self::new(
            BasicToken::CLIENT_ID,
            BasicToken::CLIENT_SECRET,
            BasicTokenLength::Length112,
        )
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<String> for BasicToken {
    /// Convert a String into a BasicToken
    ///
    /// ? This assumes the string is base64 encoded
    fn from(s: String) -> Self {
        Self(s)
    }
}
