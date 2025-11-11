// Example JavaScript rule file demonstrating console API usage
// This can be used with: httpjail --js-file examples/console_log_demo.js ...
//
// Console output is visible when running with appropriate log levels:
// RUST_LOG=debug httpjail --js-file examples/console_log_demo.js ...   # Shows debug/log
// RUST_LOG=info httpjail --js-file examples/console_log_demo.js ...    # Shows info/warn/error
// RUST_LOG=warn httpjail --js-file examples/console_log_demo.js ...    # Shows warn/error

// Different console methods map to tracing levels:
// console.debug() -> DEBUG
// console.log()   -> INFO
// console.info()  -> INFO
// console.warn()  -> WARN
// console.error() -> ERROR

// Debug: detailed information for troubleshooting
console.debug("Evaluating request:", r.method, r.url);
console.debug("Full request object:", r);

// Log: general informational messages
console.log("Requester IP:", r.requester_ip);

// Example: Allow only GET requests to example.com
if (r.method === "GET" && r.url.includes("example.com")) {
    console.info("Allowing request to example.com");
    true
} else if (r.url.includes("suspicious-site.com")) {
    console.error("Blocked suspicious site:", r.url);
    ({deny_message: "Blocked: suspicious site"})
} else {
    console.warn("Denying request - not example.com or not GET");
    ({deny_message: "Only GET requests to example.com are allowed"})
}
