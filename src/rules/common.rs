use hyper::Method;
use serde::{Deserialize, Serialize};
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

/// Common response structure for rule engines (proc and v8_js)
/// This ensures perfect parity between different evaluation modes
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_message: Option<String>,
}

impl RuleResponse {
    /// Parse a response from various formats
    /// Supports:
    /// - "true" / "false" strings
    /// - JSON objects with allow and/or deny_message fields
    /// - Any other string is treated as a deny with that message
    pub fn from_string(s: &str) -> Self {
        let trimmed = s.trim();

        // Handle simple boolean strings
        match trimmed {
            "true" => {
                return RuleResponse {
                    allow: Some(true),
                    deny_message: None,
                };
            }
            "false" => {
                return RuleResponse {
                    allow: Some(false),
                    deny_message: None,
                };
            }
            _ => {}
        }

        // Try to parse as JSON
        if let Ok(response) = serde_json::from_str::<RuleResponse>(trimmed) {
            return response;
        }

        // Any other output is treated as deny with the output as the message
        RuleResponse {
            allow: Some(false),
            deny_message: Some(trimmed.to_string()),
        }
    }

    /// Convert to evaluation result tuple (allowed, context)
    /// Following the rules:
    /// - If deny_message exists but allow is not set, default to deny
    /// - Only include context message when denying
    pub fn to_evaluation_result(&self) -> (bool, Option<String>) {
        let allowed = self.allow.unwrap_or_else(|| {
            // If allow is not specified but deny_message exists, default to false
            self.deny_message.is_none()
        });

        if allowed {
            (true, None) // Never include message when allowing
        } else {
            (false, self.deny_message.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_response_from_string() {
        // Test simple boolean strings
        let resp = RuleResponse::from_string("true");
        assert_eq!(resp.allow, Some(true));
        assert_eq!(resp.deny_message, None);

        let resp = RuleResponse::from_string("false");
        assert_eq!(resp.allow, Some(false));
        assert_eq!(resp.deny_message, None);

        // Test JSON with both fields
        let resp = RuleResponse::from_string(r#"{"allow": true}"#);
        assert_eq!(resp.allow, Some(true));
        assert_eq!(resp.deny_message, None);

        let resp = RuleResponse::from_string(r#"{"allow": false, "deny_message": "blocked"}"#);
        assert_eq!(resp.allow, Some(false));
        assert_eq!(resp.deny_message, Some("blocked".to_string()));

        // Test shorthand (deny_message only implies allow: false)
        let resp = RuleResponse::from_string(r#"{"deny_message": "not allowed"}"#);
        assert_eq!(resp.allow, None); // Note: allow is None, not Some(false)
        assert_eq!(resp.deny_message, Some("not allowed".to_string()));

        // Test arbitrary string treated as deny message
        let resp = RuleResponse::from_string("Access denied for security reasons");
        assert_eq!(resp.allow, Some(false));
        assert_eq!(
            resp.deny_message,
            Some("Access denied for security reasons".to_string())
        );

        // Test whitespace handling
        let resp = RuleResponse::from_string("  true  \n");
        assert_eq!(resp.allow, Some(true));
        assert_eq!(resp.deny_message, None);
    }

    #[test]
    fn test_rule_response_to_evaluation_result() {
        // Allow with no message
        let resp = RuleResponse {
            allow: Some(true),
            deny_message: None,
        };
        assert_eq!(resp.to_evaluation_result(), (true, None));

        // Allow with message (message should be ignored)
        let resp = RuleResponse {
            allow: Some(true),
            deny_message: Some("ignored".to_string()),
        };
        assert_eq!(resp.to_evaluation_result(), (true, None));

        // Deny with message
        let resp = RuleResponse {
            allow: Some(false),
            deny_message: Some("denied".to_string()),
        };
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("denied".to_string()))
        );

        // Deny without message
        let resp = RuleResponse {
            allow: Some(false),
            deny_message: None,
        };
        assert_eq!(resp.to_evaluation_result(), (false, None));

        // Shorthand: deny_message only (implies deny)
        let resp = RuleResponse {
            allow: None,
            deny_message: Some("blocked".to_string()),
        };
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("blocked".to_string()))
        );

        // Neither field set (defaults to allow)
        let resp = RuleResponse {
            allow: None,
            deny_message: None,
        };
        assert_eq!(resp.to_evaluation_result(), (true, None));
    }

    #[test]
    fn test_response_parity_examples() {
        // These test cases should produce identical results in both proc and v8 engines

        // Case 1: Simple true
        let resp = RuleResponse::from_string("true");
        assert_eq!(resp.to_evaluation_result(), (true, None));

        // Case 2: Simple false
        let resp = RuleResponse::from_string("false");
        assert_eq!(resp.to_evaluation_result(), (false, None));

        // Case 3: JSON allow
        let resp = RuleResponse::from_string(r#"{"allow": true}"#);
        assert_eq!(resp.to_evaluation_result(), (true, None));

        // Case 4: JSON deny with message
        let resp =
            RuleResponse::from_string(r#"{"allow": false, "deny_message": "Not authorized"}"#);
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("Not authorized".to_string()))
        );

        // Case 5: Shorthand deny
        let resp = RuleResponse::from_string(r#"{"deny_message": "Access restricted"}"#);
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("Access restricted".to_string()))
        );

        // Case 6: Plain text message
        let resp = RuleResponse::from_string("Invalid request");
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("Invalid request".to_string()))
        );
    }
}
