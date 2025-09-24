use criterion::{Criterion, criterion_group, criterion_main};
use httpjail::rules::{
    RuleEngine, proc::ProcRuleEngine, shell::ShellRuleEngine, v8_js::V8JsRuleEngine,
};
use httpjail::test_utils::create_program_file;
use hyper::Method;
use std::time::Duration;

fn bench_v8_js_engine(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let engine = V8JsRuleEngine::new("true".to_string()).unwrap();
    let engine = RuleEngine::from_trait(Box::new(engine), None);

    c.bench_function("v8_js_engine", |b| {
        b.to_async(&runtime)
            .iter(|| async { engine.evaluate(Method::GET, "https://example.com").await });
    });
}

fn bench_shell_engine(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let engine = ShellRuleEngine::new("true".to_string());
    let engine = RuleEngine::from_trait(Box::new(engine), None);

    c.bench_function("shell_engine", |b| {
        b.to_async(&runtime)
            .iter(|| async { engine.evaluate(Method::GET, "https://example.com").await });
    });
}

fn bench_proc_engine(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    // Create a simple interactive program that stays alive and responds quickly
    let program = r#"#!/bin/sh
while IFS= read -r line; do
    echo "true"
done
"#;

    let program_path = create_program_file(program);
    let engine = ProcRuleEngine::new(program_path.to_str().unwrap().to_string());
    let engine = RuleEngine::from_trait(Box::new(engine), None);

    c.bench_function("proc_engine", |b| {
        b.to_async(&runtime)
            .iter(|| async { engine.evaluate(Method::GET, "https://example.com").await });
    });
}

fn create_criterion() -> Criterion {
    let mut criterion = Criterion::default().measurement_time(Duration::from_secs(10));

    // Enable profiling if --profile flag is passed
    // Usage: cargo bench -- --profile-time 10
    if std::env::args().any(|arg| arg.contains("--profile-time")) {
        use pprof::criterion::{Output, PProfProfiler};
        criterion = criterion.with_profiler(PProfProfiler::new(100, Output::Protobuf));
    }

    criterion
}

criterion_group! {
    name = benches;
    config = create_criterion();
    targets = bench_v8_js_engine, bench_shell_engine, bench_proc_engine
}

criterion_main!(benches);
