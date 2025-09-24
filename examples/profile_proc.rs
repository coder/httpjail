#[cfg(feature = "profile")]
use pprof::{ProfilerGuardBuilder, protos::Message};
#[cfg(feature = "profile")]
use std::fs::File;
#[cfg(feature = "profile")]
use std::io::Write;

use httpjail::rules::{RuleEngine, proc::ProcRuleEngine};
use hyper::Method;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the engine once
    let engine = ProcRuleEngine::new("yes true".to_string());
    let engine = RuleEngine::from_trait(Box::new(engine), None);

    #[cfg(feature = "profile")]
    {
        // Start profiling
        let guard = ProfilerGuardBuilder::default()
            .frequency(1000)
            .blocklist(&["libc", "libpthread", "libdl"])
            .build()?;

        // Run many iterations to get good profiling data
        for _ in 0..1000 {
            engine.evaluate(Method::GET, "https://example.com").await;
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

        let mut file = File::create("profile.pb.gz")?;
        file.write_all(&compressed)?;

        println!("Profile saved to profile.pb.gz");
        println!("View with: go tool pprof profile.pb.gz");
    }

    #[cfg(not(feature = "profile"))]
    {
        // Run many iterations
        for _ in 0..1000 {
            engine.evaluate(Method::GET, "https://example.com").await;
        }
        println!("Run with --features profile to generate pprof output");
    }

    Ok(())
}
