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

/// Policy for allowing requests
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum AllowPolicy {
    /// Simple boolean allow/deny
    Bool(bool),
    /// Allow with byte transmission limit
    Limited { max_tx_bytes: u64 },
}

impl<'de> Deserialize<'de> for AllowPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        use serde_json::Value;

        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Bool(b) => Ok(AllowPolicy::Bool(b)),
            Value::Object(mut obj) => {
                if let Some(max_tx_bytes) = obj.remove("max_tx_bytes") {
                    let bytes = max_tx_bytes
                        .as_u64()
                        .ok_or_else(|| Error::custom("max_tx_bytes must be a number"))?;
                    Ok(AllowPolicy::Limited {
                        max_tx_bytes: bytes,
                    })
                } else {
                    Err(Error::custom(
                        "allow object must contain max_tx_bytes field",
                    ))
                }
            }
            _ => Err(Error::custom("allow must be a boolean or object")),
        }
    }
}

/// Common response structure for rule engines (proc and v8_js)
/// This ensures perfect parity between different evaluation modes
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<AllowPolicy>,
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
                    allow: Some(AllowPolicy::Bool(true)),
                    deny_message: None,
                };
            }
            "false" => {
                return RuleResponse {
                    allow: Some(AllowPolicy::Bool(false)),
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
            allow: Some(AllowPolicy::Bool(false)),
            deny_message: Some(trimmed.to_string()),
        }
    }

    /// Convert to evaluation result tuple (allowed, context, max_tx_bytes)
    /// Following the rules:
    /// - If deny_message exists but allow is not set, default to deny
    /// - Only include context message when denying
    /// - max_tx_bytes is returned when allow policy has a byte limit
    pub fn to_evaluation_result(&self) -> (bool, Option<String>, Option<u64>) {
        match &self.allow {
            Some(AllowPolicy::Bool(true)) => (true, None, None),
            Some(AllowPolicy::Bool(false)) => (false, self.deny_message.clone(), None),
            Some(AllowPolicy::Limited { max_tx_bytes }) => (true, None, Some(*max_tx_bytes)),
            None => {
                // If allow is not specified but deny_message exists, default to deny
                let allowed = self.deny_message.is_none();
                if allowed {
                    (true, None, None)
                } else {
                    (false, self.deny_message.clone(), None)
                }
            }
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
        assert!(matches!(resp.allow, Some(AllowPolicy::Bool(true))));
        assert_eq!(resp.deny_message, None);

        let resp = RuleResponse::from_string("false");
        assert!(matches!(resp.allow, Some(AllowPolicy::Bool(false))));
        assert_eq!(resp.deny_message, None);

        // Test JSON with both fields
        let resp = RuleResponse::from_string(r#"{"allow": true}"#);
        assert!(matches!(resp.allow, Some(AllowPolicy::Bool(true))));
        assert_eq!(resp.deny_message, None);

        let resp = RuleResponse::from_string(r#"{"allow": false, "deny_message": "blocked"}"#);
        assert!(matches!(resp.allow, Some(AllowPolicy::Bool(false))));
        assert_eq!(resp.deny_message, Some("blocked".to_string()));

        // Test shorthand (deny_message only implies allow: false)
        let resp = RuleResponse::from_string(r#"{"deny_message": "not allowed"}"#);
        assert_eq!(resp.allow, None); // Note: allow is None, not Some(false)
        assert_eq!(resp.deny_message, Some("not allowed".to_string()));

        // Test arbitrary string treated as deny message
        let resp = RuleResponse::from_string("Access denied for security reasons");
        assert!(matches!(resp.allow, Some(AllowPolicy::Bool(false))));
        assert_eq!(
            resp.deny_message,
            Some("Access denied for security reasons".to_string())
        );

        // Test whitespace handling
        let resp = RuleResponse::from_string("  true  \n");
        assert!(matches!(resp.allow, Some(AllowPolicy::Bool(true))));
        assert_eq!(resp.deny_message, None);
    }

    #[test]
    fn test_rule_response_to_evaluation_result() {
        // Allow with no message
        let resp = RuleResponse {
            allow: Some(AllowPolicy::Bool(true)),
            deny_message: None,
        };
        assert_eq!(resp.to_evaluation_result(), (true, None, None));

        // Allow with message (message should be ignored)
        let resp = RuleResponse {
            allow: Some(AllowPolicy::Bool(true)),
            deny_message: Some("ignored".to_string()),
        };
        assert_eq!(resp.to_evaluation_result(), (true, None, None));

        // Deny with message
        let resp = RuleResponse {
            allow: Some(AllowPolicy::Bool(false)),
            deny_message: Some("denied".to_string()),
        };
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("denied".to_string()), None)
        );

        // Deny without message
        let resp = RuleResponse {
            allow: Some(AllowPolicy::Bool(false)),
            deny_message: None,
        };
        assert_eq!(resp.to_evaluation_result(), (false, None, None));

        // Shorthand: deny_message only (implies deny)
        let resp = RuleResponse {
            allow: None,
            deny_message: Some("blocked".to_string()),
        };
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("blocked".to_string()), None)
        );

        // Neither field set (defaults to allow)
        let resp = RuleResponse {
            allow: None,
            deny_message: None,
        };
        assert_eq!(resp.to_evaluation_result(), (true, None, None));
    }

    #[test]
    fn test_response_parity_examples() {
        // These test cases should produce identical results in both proc and v8 engines

        // Case 1: Simple true
        let resp = RuleResponse::from_string("true");
        assert_eq!(resp.to_evaluation_result(), (true, None, None));

        // Case 2: Simple false
        let resp = RuleResponse::from_string("false");
        assert_eq!(resp.to_evaluation_result(), (false, None, None));

        // Case 3: JSON allow
        let resp = RuleResponse::from_string(r#"{"allow": true}"#);
        assert_eq!(resp.to_evaluation_result(), (true, None, None));

        // Case 4: JSON deny with message
        let resp =
            RuleResponse::from_string(r#"{"allow": false, "deny_message": "Not authorized"}"#);
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("Not authorized".to_string()), None)
        );

        // Case 5: Shorthand deny
        let resp = RuleResponse::from_string(r#"{"deny_message": "Access restricted"}"#);
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("Access restricted".to_string()), None)
        );

        // Case 6: Plain text message
        let resp = RuleResponse::from_string("Invalid request");
        assert_eq!(
            resp.to_evaluation_result(),
            (false, Some("Invalid request".to_string()), None)
        );
    }

    #[test]
    fn test_allow_with_max_tx_bytes() {
        // Test parsing allow with max_tx_bytes
        let resp = RuleResponse::from_string(r#"{"allow": {"max_tx_bytes": 1024}}"#);
        assert!(matches!(
            resp.allow,
            Some(AllowPolicy::Limited { max_tx_bytes: 1024 })
        ));
        assert_eq!(resp.deny_message, None);
        assert_eq!(resp.to_evaluation_result(), (true, None, Some(1024)));

        // Test parsing allow with large max_tx_bytes
        let resp = RuleResponse::from_string(r#"{"allow": {"max_tx_bytes": 10485760}}"#);
        assert!(matches!(
            resp.allow,
            Some(AllowPolicy::Limited {
                max_tx_bytes: 10485760
            })
        ));
        assert_eq!(resp.to_evaluation_result(), (true, None, Some(10485760)));

        // Test that deny_message is ignored when max_tx_bytes is set
        let resp = RuleResponse::from_string(
            r#"{"allow": {"max_tx_bytes": 512}, "deny_message": "ignored"}"#,
        );
        assert!(matches!(
            resp.allow,
            Some(AllowPolicy::Limited { max_tx_bytes: 512 })
        ));
        assert_eq!(resp.to_evaluation_result(), (true, None, Some(512)));
    }
}
