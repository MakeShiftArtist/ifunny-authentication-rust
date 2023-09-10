
#[derive(Debug)]
pub enum Error {
    BoxError(Box<dyn std::error::Error>),
    ReqwestError(reqwest::Error),
    JsonError(json::Error),
    CaptchaRequired {
        captcha_url: String
    },
    UnknownError
}