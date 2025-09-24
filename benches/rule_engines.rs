#[cfg(feature = "profile")]
use criterion::Criterion;
#[cfg(not(feature = "profile"))]
use criterion::{Criterion, criterion_group, criterion_main};

use httpjail::rules::{
    RuleEngine, proc::ProcRuleEngine, shell::ShellRuleEngine, v8_js::V8JsRuleEngine,
};
use hyper::Method;

#[cfg(not(feature = "profile"))]
use std::time::Duration;

#[cfg(feature = "profile")]
use pprof::{ProfilerGuardBuilder, protos::Message};
#[cfg(feature = "profile")]
use std::fs::File;
#[cfg(feature = "profile")]
use std::io::Write;

#[cfg_attr(feature = "profile", allow(dead_code))]
fn bench_v8_js_engine(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let engine = V8JsRuleEngine::new("true".to_string()).unwrap();
    let engine = RuleEngine::from_trait(Box::new(engine), None);

    c.bench_function("v8_js_engine", |b| {
        b.to_async(&runtime)
            .iter(|| async { engine.evaluate(Method::GET, "https://example.com").await });
    });
}

#[cfg_attr(feature = "profile", allow(dead_code))]
fn bench_shell_engine(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let engine = ShellRuleEngine::new("true".to_string());
    let engine = RuleEngine::from_trait(Box::new(engine), None);

    c.bench_function("shell_engine", |b| {
        b.to_async(&runtime)
            .iter(|| async { engine.evaluate(Method::GET, "https://example.com").await });
    });
}

#[cfg_attr(feature = "profile", allow(dead_code))]
fn bench_proc_engine(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let engine = ProcRuleEngine::new("yes true".to_string());
    let engine = RuleEngine::from_trait(Box::new(engine), None);

    c.bench_function("proc_engine", |b| {
        b.to_async(&runtime)
            .iter(|| async { engine.evaluate(Method::GET, "https://example.com").await });
    });
}

#[cfg(feature = "profile")]
async fn profile_engines() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running profiling mode for proc engine...");

    // Create proc engine
    let proc_engine = ProcRuleEngine::new("yes true".to_string());
    let proc_engine = RuleEngine::from_trait(Box::new(proc_engine), None);

    // Start profiling
    let guard = ProfilerGuardBuilder::default()
        .frequency(1000)
        .blocklist(&["libc", "libpthread", "libdl"])
        .build()?;

    // Run many iterations for proc engine
    println!("Profiling Proc engine (10000 iterations)...");
    for i in 0..10000 {
        if i % 1000 == 0 {
            println!("  Progress: {}/10000", i);
        }
        proc_engine
            .evaluate(Method::GET, "https://example.com")
            .await;
    }

    // Generate the profile
    let report = guard.report().build()?;

    // Write pprof protobuf format
    let profile = report.pprof()?;
    let mut content = Vec::new();
    profile.write_to_vec(&mut content)?;

    // Compress with gzip
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&content)?;
    let compressed = encoder.finish()?;

    let mut file = File::create("proc_engine_profile.pb.gz")?;
    file.write_all(&compressed)?;

    println!("Profile saved to proc_engine_profile.pb.gz");
    println!("View with: go tool pprof proc_engine_profile.pb.gz");

    Ok(())
}

#[cfg(not(feature = "profile"))]
criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10));
    targets = bench_v8_js_engine, bench_shell_engine, bench_proc_engine
}

#[cfg(not(feature = "profile"))]
criterion_main!(benches);

#[cfg(feature = "profile")]
fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(profile_engines()).unwrap();
}
