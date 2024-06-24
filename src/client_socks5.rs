use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use tokio::net::lookup_host;
use tokio::time::{timeout, Duration};

const LOCAL_PORT: u16 = 12345; // Local listening HTTP port
const SOCKS_SERVER_ADDR: &str = "xxx:6969"; // Remote SOCKS proxy server address
const KEY: &[u8] = b"01234567890123456789012345678901"; // Replace with your encryption key

async fn handle_http_to_socks(mut client_stream: TcpStream) -> Result<(), Box<dyn Error>> {
    // Read HTTP request header
    let mut buf = vec![0; 4096];
    let mut total_read = 0;

    loop {
        let read_result = timeout(Duration::from_secs(10), client_stream.read(&mut buf[total_read..])).await;
        match read_result {
            Ok(Ok(0)) => {
                eprintln!("Client closed the connection prematurely");
                return Err("Client closed connection".into());
            }
            Ok(Ok(n)) => {
                total_read += n;
                if buf[..total_read].windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                if total_read >= buf.len() {
                    return Err("HTTP request too large".into());
                }
            }
            Ok(Err(e)) => {
                eprintln!("Error reading HTTP request: {:?}", e);
                return Err("Failed to read HTTP request".into());
            }
            Err(_) => {
                eprintln!("Timeout reading HTTP request");
                return Err("Timeout reading HTTP request".into());
            }
        }
    }

    println!("Received HTTP request:\n{}", String::from_utf8_lossy(&buf[..total_read]));

    // Parse HTTP request, extract target host, port, and other information
    let (target_host, target_port) = parse_http_request(&buf[..total_read])?;
    println!("Received HTTP request for {}:{}", target_host, target_port);

    // Connect to the remote SOCKS proxy server
    let mut socks_stream = TcpStream::connect(SOCKS_SERVER_ADDR).await?;

    // SOCKS5 handshake
    socks_stream.write_all(&[0x05, 0x01, 0x00]).await?; // SOCKS5, 1 method, NO AUTH
    let mut handshake_response = [0; 2];
    socks_stream.read_exact(&mut handshake_response).await?;
    if handshake_response[0] != 0x05 || handshake_response[1] != 0x00 {
        return Err("SOCKS5 handshake failed".into());
    }

    // Construct SOCKS5 request
    let socks_request = build_socks5_request(&target_host, target_port)?;

    // Send SOCKS5 request to the SOCKS proxy server
    socks_stream.write_all(&socks_request).await?;

    // Receive response from the SOCKS proxy server
    let mut socks_response = vec![0; 10]; // Initially read the first 10 bytes of the response
    socks_stream.read_exact(&mut socks_response).await?;
    if socks_response[1] != 0x00 {
        eprintln!("SOCKS5 request failed with code {}", socks_response[1]);
        return Ok(());
    }

    // Read target address type
    let addr_type = socks_response[3];
    if addr_type == 0x01 { // IPv4
        socks_response.resize(10 + 4, 0); // Read additional 4 bytes
    } else if addr_type == 0x04 { // IPv6
        socks_response.resize(10 + 16, 0); // Read additional 16 bytes
    } else if addr_type == 0x03 { // Domain name
        let domain_len = socks_stream.read_u8().await? as usize;
        socks_response.resize(10 + domain_len + 2, 0); // Read domain name length and port
    }
    socks_stream.read_exact(&mut socks_response[10..]).await?;

    println!("Connected to SOCKS proxy and target server");

    // Data forwarding
    let (mut client_read, mut client_write) = client_stream.into_split();
    let (mut socks_read, mut socks_write) = socks_stream.into_split();

    tokio::spawn(async move {
        let mut buffer = [0; 1024];
        loop {
            let n = match client_read.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error reading from client: {:?}", e);
                    break;
                }
            };
            if n == 0 {
                break;
            }

            // Encrypt data
            let encrypted_data = match crate::crypto::encrypt(&buffer[..n], KEY) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Encryption error: {:?}", e);
                    break;
                }
            };

            if socks_write.write_all(&encrypted_data).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let mut buffer = [0; 1024];
        loop {
            let n = match socks_read.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error reading from SOCKS: {:?}", e);
                    break;
                }
            };
            if n == 0 {
                break;
            }

            // Decrypt data
            let decrypted_data = match crate::crypto::decrypt(&buffer[..n], KEY) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Decryption error: {:?}", e);
                    break;
                }
            };

            if client_write.write_all(&decrypted_data).await.is_err() {
                break;
            }
        }
    });

    Ok(())
}

fn parse_http_request(request: &[u8]) -> Result<(String, u16), Box<dyn Error>> {
    let request_str = std::str::from_utf8(request)?;

    // Split request line and header information
    let mut lines = request_str.lines();
    let request_line = lines.next().ok_or("Invalid HTTP request")?;

    // Parse request line
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().ok_or("Invalid HTTP request")?;
    let url = parts.next().ok_or("Invalid HTTP request")?;
    let _version = parts.next().ok_or("Invalid HTTP request")?;

    // Extract hostname and port number
    let (mut host, mut port) = if url.starts_with("http://") {
        extract_host_and_port(&url[7..], 80)?
    } else if url.starts_with("https://") {
        extract_host_and_port(&url[8..], 443)?
    } else {
        (None, 80)
    };

    // If no hostname found in the request line, look for Host header
    if host.is_none() {
        for line in lines {
            if line.to_lowercase().starts_with("host:") {
                let host_line = line[5..].trim();
                let (parsed_host, parsed_port) = extract_host_and_port(host_line, port)?;
                host = parsed_host;
                port = parsed_port;
                break;
            }
        }
    }

    let host = host.ok_or("Host not found in HTTP request")?;
    Ok((host, port))
}

// Extract hostname and port number from host string
fn extract_host_and_port(host: &str, default_port: u16) -> Result<(Option<String>, u16), Box<dyn Error>> {
    let mut host_port = host.split(':');
    let host_name = host_port.next().ok_or("Invalid host format")?;
    let port_str = host_port.next();

    let port = if let Some(port_str) = port_str {
        port_str.parse::<u16>().map_err(|_| "Invalid port number")?
    } else {
        default_port
    };

    // Remove path and query parameters
    let host_name = if let Some(pos) = host_name.find('/') {
        &host_name[..pos]
    } else {
        host_name
    };

    Ok((Some(host_name.to_string()), port))
}

// Construct SOCKS5 protocol request
fn build_socks5_request(target_host: &str, target_port: u16) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut request = vec![0x05, 0x01, 0x00]; // SOCKS5, CONNECT, NO AUTHENTICATION REQUIRED

    if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
        request.push(0x01); // Address type: IPv4
        request.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = target_host.parse::<std::net::Ipv6Addr>() {
        request.push(0x04); // Address type: IPv6
        request.extend_from_slice(&ip.octets());
    } else {
        request.push(0x03); // Address type: Domain name
        request.push(target_host.len() as u8);
        request.extend_from_slice(target_host.as_bytes());
    }

    request.extend_from_slice(&target_port.to_be_bytes());
    Ok(request)
}

// Resolve domain name to IP address
async fn resolve_domain_to_ip(domain: &str) -> Result<String, Box<dyn Error>> {
    // Use DNS to resolve hostname
    let addrs = lookup_host((domain, 0)).await?;
    for addr in addrs {
        if let std::net::SocketAddr::V4(socket_addr) = addr {
            return Ok(socket_addr.ip().to_string());
        }
    }
    Err("Failed to resolve domain to IPv4 address".into())
}


pub async fn run_client() -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", LOCAL_PORT)).await?;
    println!("Listening on port {}", LOCAL_PORT);

    loop {
        let (client_stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_http_to_socks(client_stream).await {
                eprintln!("Failed to handle connection: {:?}", e);
            }
        });
    }
}
