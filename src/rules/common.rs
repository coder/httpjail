use hyper::Method;
use serde::Serialize;
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct RequestInfo {
    pub url: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub requester_ip: String,
}

impl RequestInfo {
    pub fn from_request(method: &Method, url: &str, requester_ip: &str) -> Result<Self, String> {
        let parsed_url = Url::parse(url).map_err(|e| format!("Failed to parse URL: {}", e))?;

        Ok(RequestInfo {
            url: url.to_string(),
            method: method.as_str().to_string(),
            scheme: parsed_url.scheme().to_string(),
            host: parsed_url.host_str().unwrap_or("").to_string(),
            path: parsed_url.path().to_string(),
            requester_ip: requester_ip.to_string(),
        })
    }
}
