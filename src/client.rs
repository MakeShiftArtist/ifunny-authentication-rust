use crate::{basic::BasicToken, error::Error};
use reqwest::Client;
use std::collections::HashMap;

/// Login to iFunny and retrive the Bearer token.
///
/// This returns an Error enum that includes the captcha url when encountered.
///
/// When successful, it returns the bearer.
///
/// This must be primed by inputing the information and then waiting ten seconds to try again the first time a new basic token is used.
///
/// ## Examples
/// ```
/// use lib::client::login;
/// use lib::basic::BasicGenerator;
/// let basic = BasicGenerator::generate();
/// let username = "username".to_string();
/// let password = "password".to_string();
/// login(&username, &password, &basic);
/// // Sleep ten seconds
/// let bearer = login(&username, &password, &basic);
/// ```
pub async fn login(
    username: &String,
    password: &String,
    basic: &BasicToken,
) -> Result<String, Error> {
    let mut form: HashMap<String, String> = HashMap::with_capacity(3);
    form.insert("grant_type".to_string(), "password".to_string());
    form.insert("username".to_string(), username.to_string());
    form.insert("password".to_string(), password.to_string());

    let response = Client::new()
        .post("https://api.ifunny.mobi/v4/oauth2/token")
        .header("accept", "application/json")
        .header("applicationstate", "1")
        .header("authorization", format!("Basic {basic}"))
        .header("connection", "Keep-Alive")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("Ifunny-Project-Id", "iFunny")
        .header(
            "User-Agent",
            "iFunny/8.28.11(23965) ipad/16.5 (Apple; iPad8,6)",
        )
        .form(&form)
        .send()
        .await
        .map_err(|e| Error::ReqwestError(e))?
        .text()
        .await
        .map_err(Error::ReqwestError)?;

    let json_data = json::parse(&response).map_err(Error::JsonError)?;

    if json_data["error"] == "captcha_required" {
        if let Some(captcha_url) = json_data["data"]["captcha_url"].as_str() {
            let captcha_url = captcha_url.to_string();
            return Err(Error::CaptchaRequired { captcha_url });
        }
    }

    if let Some(access_token) = json_data["access_token"].as_str() {
        return Ok(access_token.to_string());
    }

    let pretty_response = json::stringify_pretty(json_data, 4);

    println!("\n{pretty_response}\n");
    Err(Error::UnknownError)
}
