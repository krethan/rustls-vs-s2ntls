# rustls-vs-s2ntls
Performance benchmark comparing rustls vs s2n-tls implementations

## ⚠️ Disclaimer

**This is a testing/benchmarking project and should not be considered a definitive comparison:**

- **Testing Environment**: Results are based on specific test conditions and may not reflect real-world performance
- **Configuration Differences**: Libraries may have different default security settings and optimization levels
- **Certificate Validation**: While both libraries use proper validation, implementation details may differ
- **Benchmark Limitations**: 
  - Uses self-signed certificates rather than production CA-signed certificates
  - Tests a specific workload pattern (short-lived connections with small payloads)
  - May not represent all use cases or deployment scenarios
- **Version Specific**: Results are specific to the library versions used and may change with updates

**This benchmark is intended for educational and testing purposes only.** For production decisions, conduct your own comprehensive testing with your specific workload and environment.

## 🚀 Features

- Measures handshake time, throughput, requests per second, and memory usage
- Supports multiple test scenarios (quick test, standard load, high performance)
- Uses proper certificate validation for fair comparison
- Self-signed certificate generation for testing

## 📊 Metrics Measured

- **Handshake Time**: TLS connection establishment time
- **Throughput**: Data transfer speed in MB/s  
- **Requests/Second**: Maximum request processing rate
- **Connections/Second**: Concurrent connection handling capacity
- **Memory Usage**: Runtime memory consumption

## 🛠️ Installation

```bash
git clone https://github.com/krethan/rustls-vs-s2ntls.git
cd rustls-vs-s2ntls
cargo build --release

## 🏃‍♂️ Usage

# Run benchmark
cargo run --release

# Run tests
cargo test

## 📦 Dependencies

rustls = "0.21"
s2n-tls = "0.3"
tokio = { version = "1.0", features = ["full"] }
rcgen = "0.11"
And others... (see Cargo.toml)

## 📈 Example Results

🎯 Starting comprehensive rustls vs s2n-tls benchmark...

📊 --- Quick Test (10 iterations) ---
🔥 Benchmarking rustls with 10 iterations...
  rustls progress: 0/10
✅ rustls benchmark completed!
🔥 Benchmarking s2n-tls with 10 iterations...
  s2n-tls progress: 0/10
✅ s2n-tls benchmark completed!

🏆 === TLS Performance Benchmark Results ===
Library      Handshake(ms)   Throughput(MB/s) Requests/sec    Conn/sec        Memory(MB)  
==========================================================================================
rustls       2.05            0.01            401.11          401.11          36.32       
s2n-tls      101.49          0.00            9.75            9.75            36.32 



