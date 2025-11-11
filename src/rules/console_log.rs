use tracing::{debug, info, warn};

/// Convert a V8 value to a string, using JSON.stringify for objects
fn v8_value_to_string(scope: &mut v8::HandleScope, value: v8::Local<v8::Value>) -> String {
    // For objects and arrays, try JSON.stringify
    if value.is_object() && !value.is_null() && !value.is_undefined() {
        if let Some(json_str) = try_json_stringify(scope, value) {
            return json_str;
        }
    }

    // Fallback to toString() for all types
    value
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_else(|| "[value]".to_string())
}

/// Try to JSON.stringify a value, returning None if it fails
fn try_json_stringify(scope: &mut v8::HandleScope, value: v8::Local<v8::Value>) -> Option<String> {
    let global = scope.get_current_context().global(scope);
    let json_key = v8::String::new(scope, "JSON")?;
    let stringify_key = v8::String::new(scope, "stringify")?;

    let json_obj = global.get(scope, json_key.into())?.to_object(scope)?;
    let stringify_fn = json_obj.get(scope, stringify_key.into())?;
    let stringify_fn = v8::Local::<v8::Function>::try_from(stringify_fn).ok()?;

    let result = stringify_fn.call(scope, json_obj.into(), &[value])?;
    result
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope))
}

/// Format console arguments into a single string
fn format_console_args(scope: &mut v8::HandleScope, args: v8::FunctionCallbackArguments) -> String {
    let mut log_parts = Vec::new();
    for i in 0..args.length() {
        let arg = args.get(i);
        log_parts.push(v8_value_to_string(scope, arg));
    }
    log_parts.join(" ")
}

/// Generic console callback that logs at a specific level
fn console_callback(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _retval: v8::ReturnValue,
    log_fn: fn(&str),
) {
    let message = format_console_args(scope, args);
    log_fn(&message);
}

/// Macro to generate console method callbacks for each log level
macro_rules! console_method {
    ($name:ident, $log_macro:path) => {
        fn $name(
            scope: &mut v8::HandleScope,
            args: v8::FunctionCallbackArguments,
            retval: v8::ReturnValue,
        ) {
            console_callback(scope, args, retval, |msg| {
                $log_macro!(target: "httpjail::rules::js", "{}", msg)
            });
        }
    };
}

// Generate console.debug, console.log, console.info, console.warn, console.error
console_method!(console_debug, debug);
console_method!(console_log, info);
console_method!(console_info, info);
console_method!(console_warn, warn);
console_method!(console_error, tracing::error);

/// Set up console object with debug, log, info, warn, error methods
pub fn setup_console(context_scope: &mut v8::ContextScope<v8::HandleScope>) {
    let global = context_scope.get_current_context().global(context_scope);
    let console_obj = v8::Object::new(context_scope);

    // Register each console method
    macro_rules! add_console_method {
        ($name:expr, $callback:expr) => {
            let key = v8::String::new(context_scope, $name).unwrap();
            let func = v8::Function::new(context_scope, $callback).unwrap();
            console_obj.set(context_scope, key.into(), func.into());
        };
    }

    add_console_method!("debug", console_debug);
    add_console_method!("log", console_log);
    add_console_method!("info", console_info);
    add_console_method!("warn", console_warn);
    add_console_method!("error", console_error);

    let console_key = v8::String::new(context_scope, "console").unwrap();
    global.set(context_scope, console_key.into(), console_obj.into());
}
