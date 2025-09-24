use criterion::{Criterion, criterion_group, criterion_main};
use httpjail::rules::{
    RuleEngine, proc::ProcRuleEngine, shell::ShellRuleEngine, v8_js::V8JsRuleEngine,
};
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
    let engine = ProcRuleEngine::new("yes true".to_string());
    let engine = RuleEngine::from_trait(Box::new(engine), None);

    c.bench_function("proc_engine", |b| {
        b.to_async(&runtime)
            .iter(|| async { engine.evaluate(Method::GET, "https://example.com").await });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10));
    targets = bench_v8_js_engine, bench_shell_engine, bench_proc_engine
}

criterion_main!(benches);
