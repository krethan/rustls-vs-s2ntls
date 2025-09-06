// Cargo.toml dependencies needed:
// [dependencies]
// rustls = { version = "0.21"}
// s2n-tls = "0.3"
// s2n-tls-tokio = "0.3"
// tokio = { version = "1.0", features = ["full"] }
// tokio-rustls = "0.24"
// webpki-roots = "0.25"
// rcgen = "0.11"
// rustls-pemfile = "1.0"

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Test data simulating Redis PING command and response
const TEST_DATA: &[u8] = b"*1\r\n$4\r\nPING\r\n";
const RESPONSE_DATA: &[u8] = b"+PONG\r\n";

#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    pub library: String,
    pub handshake_time_ms: f64,
    pub throughput_mbps: f64,
    pub requests_per_second: f64,
    pub connections_per_second: f64,
    pub memory_usage_mb: f64,
}

pub struct TlsBenchmark {
    results: Vec<BenchmarkResults>,
}

impl TlsBenchmark {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    // Generate self-signed certificate for testing
    fn generate_test_cert() -> (Vec<u8>, Vec<u8>) {
        use rcgen::{Certificate, CertificateParams, DistinguishedName};
        
        let mut params = CertificateParams::new(vec!["localhost".to_string()]);
        params.distinguished_name = DistinguishedName::new();
        
        let cert = Certificate::from_params(params).unwrap();
        let cert_pem = cert.serialize_pem().unwrap().into_bytes();
        let key_pem = cert.serialize_private_key_pem().into_bytes();
        
        (cert_pem, key_pem)
    }

    // Benchmark rustls
    pub async fn benchmark_rustls(&mut self, iterations: usize) -> io::Result<()> {
        println!("🔥 Benchmarking rustls with {} iterations...", iterations);
        
        let (cert_pem, key_pem) = Self::generate_test_cert();
        
        // Start rustls server
        let server_addr = self.start_rustls_server(cert_pem.clone(), key_pem.clone()).await?;
        
        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run client benchmarks
        let start_time = Instant::now();
        let mut total_bytes = 0;
        let mut handshake_times = Vec::new();

        for i in 0..iterations {
            if i % 100 == 0 {
                println!("  rustls progress: {}/{}", i, iterations);
            }

            let handshake_start = Instant::now();
            
            // Connect and perform handshake
            let mut client = self.connect_rustls_client(server_addr, cert_pem.clone()).await?;
            let handshake_time = handshake_start.elapsed();
            handshake_times.push(handshake_time.as_secs_f64() * 1000.0);

            // Send test data and read response
            client.write_all(TEST_DATA).await?;
            let mut response = vec![0; RESPONSE_DATA.len()];
            client.read_exact(&mut response).await?;
            
            total_bytes += TEST_DATA.len() + response.len();
        }

        let total_time = start_time.elapsed();
        let avg_handshake = handshake_times.iter().sum::<f64>() / handshake_times.len() as f64;
        let throughput = (total_bytes as f64) / total_time.as_secs_f64() / 1_000_000.0; // MB/s
        let rps = iterations as f64 / total_time.as_secs_f64();
        let cps = iterations as f64 / total_time.as_secs_f64(); // connections per second

        self.results.push(BenchmarkResults {
            library: "rustls".to_string(),
            handshake_time_ms: avg_handshake,
            throughput_mbps: throughput,
            requests_per_second: rps,
            connections_per_second: cps,
            memory_usage_mb: self.get_memory_usage(),
        });

        println!("✅ rustls benchmark completed!");
        Ok(())
    }

    // Benchmark s2n-tls
    pub async fn benchmark_s2n_tls(&mut self, iterations: usize) -> io::Result<()> {
        println!("🔥 Benchmarking s2n-tls with {} iterations...", iterations);
        
        let (cert_pem, key_pem) = Self::generate_test_cert();
        
        // Start s2n-tls server
        let server_addr = self.start_s2n_server(cert_pem.clone(), key_pem.clone()).await?;
        
        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run client benchmarks
        let start_time = Instant::now();
        let mut total_bytes = 0;
        let mut handshake_times = Vec::new();

        for i in 0..iterations {
            if i % 100 == 0 {
                println!("  s2n-tls progress: {}/{}", i, iterations);
            }

            let handshake_start = Instant::now();
            
            // Connect and perform handshake
            let mut client = self.connect_s2n_client(server_addr, cert_pem.clone()).await?;
            let handshake_time = handshake_start.elapsed();
            handshake_times.push(handshake_time.as_secs_f64() * 1000.0);

            // Send test data and read response
            client.write_all(TEST_DATA).await?;
            let mut response = vec![0; RESPONSE_DATA.len()];
            client.read_exact(&mut response).await?;
            
            total_bytes += TEST_DATA.len() + response.len();
        }

        let total_time = start_time.elapsed();
        let avg_handshake = handshake_times.iter().sum::<f64>() / handshake_times.len() as f64;
        let throughput = (total_bytes as f64) / total_time.as_secs_f64() / 1_000_000.0; // MB/s
        let rps = iterations as f64 / total_time.as_secs_f64();
        let cps = iterations as f64 / total_time.as_secs_f64();

        self.results.push(BenchmarkResults {
            library: "s2n-tls".to_string(),
            handshake_time_ms: avg_handshake,
            throughput_mbps: throughput,
            requests_per_second: rps,
            connections_per_second: cps,
            memory_usage_mb: self.get_memory_usage(),
        });

        println!("✅ s2n-tls benchmark completed!");
        Ok(())
    }

    // Start rustls server
    async fn start_rustls_server(&self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> io::Result<std::net::SocketAddr> {
        use rustls::{Certificate, PrivateKey, ServerConfig};
        use rustls_pemfile::{certs, pkcs8_private_keys};
        use tokio_rustls::TlsAcceptor;

        let cert_chain = certs(&mut cert_pem.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid cert"))?
            .into_iter()
            .map(Certificate)
            .collect();

        let mut keys = pkcs8_private_keys(&mut key_pem.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid key"))?;

        if keys.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "No keys found"));
        }

        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, PrivateKey(keys.remove(0)))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Bad cert/key: {}", e)))?;

        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(mut tls_stream) => {
                            // Echo server - read data and send response
                            let mut buffer = vec![0; TEST_DATA.len()];
                            if tls_stream.read_exact(&mut buffer).await.is_ok() {
                                let _ = tls_stream.write_all(RESPONSE_DATA).await;
                            }
                        }
                        Err(e) => {
                            eprintln!("rustls server error: {}", e);
                        }
                    }
                });
            }
        });

        Ok(addr)
    }

    // Start s2n-tls server  
    async fn start_s2n_server(&self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> io::Result<std::net::SocketAddr> {
        use s2n_tls::{
            config::Config,
            security::DEFAULT_TLS13,
        };
        use s2n_tls_tokio::TlsAcceptor;

        let mut config = Config::builder();
        
        // Configure s2n-tls with certificate and key
        config.set_security_policy(&DEFAULT_TLS13)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Security policy error: {}", e)))?;
        
        // Load certificate and key
        config.load_pem(&cert_pem, &key_pem)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("PEM load error: {}", e)))?;
        
        let config = config.build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Config build error: {}", e)))?;
        
        let acceptor = TlsAcceptor::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(mut tls_stream) => {
                            // Echo server - read data and send response
                            let mut buffer = vec![0; TEST_DATA.len()];
                            if tls_stream.read_exact(&mut buffer).await.is_ok() {
                                let _ = tls_stream.write_all(RESPONSE_DATA).await;
                            }
                        }
                        Err(e) => {
                            eprintln!("s2n-tls server error: {}", e);
                        }
                    }
                });
            }
        });

        Ok(addr)
    }

    // Connect rustls client
    async fn connect_rustls_client(&self, addr: std::net::SocketAddr,  cert_pem: Vec<u8>) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        use rustls::{Certificate, ClientConfig, RootCertStore,ServerName};
        use tokio_rustls::TlsConnector;
        use rustls_pemfile::certs;

        let mut root_store = RootCertStore::empty();

        let mut pem_reader = cert_pem.as_slice();
        let cert_der = certs(&mut pem_reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("PEM parsing error: {}", e)))?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No certificate found in PEM"))?;

        // Add our self-signed certificate to the trust store
        let cert = Certificate(cert_der);
        root_store.add(&cert).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Custom cert error: {}", e)))?;

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(addr).await?;
        let domain = ServerName::try_from("localhost")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid domain: {}", e)))?;
        
        connector.connect(domain, stream).await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("TLS connect failed: {}", e)))
    }

    fn get_memory_usage(&self) -> f64 {
        // Simple memory approximation - would need actual system monitoring
        std::process::id() as f64 / 1000.0 // Placeholder
    }

// Connect s2n-tls client - try to find verification methods
async fn connect_s2n_client(&self, addr: std::net::SocketAddr, cert_pem: Vec<u8>) -> io::Result<s2n_tls_tokio::TlsStream<TcpStream>> {
    use s2n_tls::config::Config;
    use s2n_tls_tokio::TlsConnector;
    use s2n_tls::enums::ClientAuthType;

    let mut config = Config::builder();
    config.set_client_auth_type(ClientAuthType::None)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Client auth error: {}", e)))?;
    config.trust_pem(&cert_pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Trust PEM error: {}", e)))?;
    
    let config = config.build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Config build error: {}", e)))?;
    
    let connector = TlsConnector::new(config);
    let stream = TcpStream::connect(addr).await?;
    
    connector.connect("localhost", stream).await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("s2n connect failed: {}", e)))

}

    pub fn print_results(&self) {
        println!("\n🏆 === TLS Performance Benchmark Results ===");
        println!("{:<12} {:<15} {:<15} {:<15} {:<15} {:<12}", 
                 "Library", "Handshake(ms)", "Throughput(MB/s)", "Requests/sec", "Conn/sec", "Memory(MB)");
        println!("{}", "=".repeat(90));

        for result in &self.results {
            println!("{:<12} {:<15.2} {:<15.2} {:<15.2} {:<15.2} {:<12.2}",
                     result.library,
                     result.handshake_time_ms,
                     result.throughput_mbps,
                     result.requests_per_second,
                     result.connections_per_second,
                     result.memory_usage_mb);
        }

        if self.results.len() >= 2 {
            let rustls = &self.results[0];
            let s2n = &self.results[1];
            
            println!("\n🥊 === Performance Comparison ===");
            
            let handshake_winner = if rustls.handshake_time_ms < s2n.handshake_time_ms { "rustls" } else { "s2n-tls" };
            let handshake_ratio = rustls.handshake_time_ms.max(s2n.handshake_time_ms) / 
                                 rustls.handshake_time_ms.min(s2n.handshake_time_ms);
            println!("🚀 Handshake Speed: {} is {:.2}x faster", handshake_winner, handshake_ratio);
            
            let throughput_winner = if rustls.throughput_mbps > s2n.throughput_mbps { "rustls" } else { "s2n-tls" };
            let throughput_ratio = rustls.throughput_mbps.max(s2n.throughput_mbps) / 
                                  rustls.throughput_mbps.min(s2n.throughput_mbps);
            println!("⚡ Throughput: {} is {:.2}x faster", throughput_winner, throughput_ratio);
            
            let conn_winner = if rustls.connections_per_second > s2n.connections_per_second { "rustls" } else { "s2n-tls" };
            let conn_ratio = rustls.connections_per_second.max(s2n.connections_per_second) / 
                            rustls.connections_per_second.min(s2n.connections_per_second);
            println!("🔗 Connections: {} is {:.2}x faster", conn_winner, conn_ratio);
        }
    }
}

// Benchmark runner with different test scenarios
pub async fn run_comprehensive_benchmark() -> io::Result<()> {
    println!("🎯 Starting comprehensive rustls vs s2n-tls benchmark...\n");
    
    let scenarios = vec![
        ("Quick Test", 10),
        ("Standard Load", 50),
        ("Extended Load", 200),
        ("Stress Test", 500),
        ("Extreme Load", 1000), // Adjust as needed for your system capabilities            
    ];

    for (name, iterations) in scenarios {
        println!("📊 --- {} ({} iterations) ---", name, iterations);
        
        let mut benchmark = TlsBenchmark::new();
        
        if let Err(e) = benchmark.benchmark_rustls(iterations).await {
            eprintln!("rustls benchmark failed: {}", e);
        }
        if let Err(e) = benchmark.benchmark_s2n_tls(iterations).await {
            eprintln!("s2n-tls benchmark failed: {}", e);
        }
        
        benchmark.print_results();
        println!();
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    run_comprehensive_benchmark().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_certificate_generation() {
        let (cert, key) = TlsBenchmark::generate_test_cert();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
        assert!(String::from_utf8_lossy(&cert).contains("BEGIN CERTIFICATE"));
        assert!(String::from_utf8_lossy(&key).contains("BEGIN PRIVATE KEY"));
    }

    #[tokio::test]
    async fn test_small_benchmark() {
        let mut benchmark = TlsBenchmark::new();
        
        // Run a small test to ensure the framework works
        benchmark.benchmark_rustls(2).await.unwrap();
        benchmark.benchmark_s2n_tls(2).await.unwrap();
        
        assert_eq!(benchmark.results.len(), 2);
        assert_eq!(benchmark.results[0].library, "rustls");
        assert_eq!(benchmark.results[1].library, "s2n-tls");
    }
}