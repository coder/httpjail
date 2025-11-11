// Example JavaScript rule file demonstrating console.log() usage
// This can be used with: httpjail --rule-js examples/console_log_demo.js ...
//
// console.log() output is visible when running with:
// RUST_LOG=debug httpjail --rule-js examples/console_log_demo.js ...

// Log information about the request
console.log("Evaluating request:", r.method, r.url);
console.log("Requester IP:", r.ip);

// Log the full request object
console.log("Full request object:", r);

// Example: Allow only GET requests to example.com
if (r.method === "GET" && r.url.includes("example.com")) {
    console.log("Allowing request to example.com");
    true
} else {
    console.log("Denying request - not example.com or not GET");
    ({deny_message: "Only GET requests to example.com are allowed"})
}
