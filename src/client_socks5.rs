use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use tokio::net::lookup_host;
use tokio::time::{timeout, Duration};

const LOCAL_PORT: u16 = 12345; // 本地监听的 HTTP 端口
const SOCKS_SERVER_ADDR: &str = "xxx:6969"; // 远程 SOCKS 代理服务器地址
const KEY: &[u8] = b"01234567890123456789012345678901"; // 替换为你的加密密钥

async fn handle_http_to_socks(mut client_stream: TcpStream) -> Result<(), Box<dyn Error>> {
    // 读取 HTTP 请求头部
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

    // 解析 HTTP 请求，提取目标主机和端口等信息
    let (target_host, target_port) = parse_http_request(&buf[..total_read])?;
    println!("Received HTTP request for {}:{}", target_host, target_port);

    // 连接远程 SOCKS 代理服务器
    let mut socks_stream = TcpStream::connect(SOCKS_SERVER_ADDR).await?;

    // SOCKS5 握手
    socks_stream.write_all(&[0x05, 0x01, 0x00]).await?; // SOCKS5, 1 method, NO AUTH
    let mut handshake_response = [0; 2];
    socks_stream.read_exact(&mut handshake_response).await?;
    if handshake_response[0] != 0x05 || handshake_response[1] != 0x00 {
        return Err("SOCKS5 handshake failed".into());
    }

    // 构造 SOCKS5 请求
    let socks_request = build_socks5_request(&target_host, target_port)?;

    // 发送 SOCKS5 请求到 SOCKS 代理服务器
    socks_stream.write_all(&socks_request).await?;

    // 接收 SOCKS 代理服务器的响应
    let mut socks_response = vec![0; 10]; // 初步读取响应前 10 字节
    socks_stream.read_exact(&mut socks_response).await?;
    if socks_response[1] != 0x00 {
        eprintln!("SOCKS5 request failed with code {}", socks_response[1]);
        return Ok(());
    }

    // 读取目标地址类型
    let addr_type = socks_response[3];
    if addr_type == 0x01 { // IPv4
        socks_response.resize(10 + 4, 0); // 再读取 4 个字节
    } else if addr_type == 0x04 { // IPv6
        socks_response.resize(10 + 16, 0); // 再读取 16 个字节
    } else if addr_type == 0x03 { // 域名
        let domain_len = socks_stream.read_u8().await? as usize;
        socks_response.resize(10 + domain_len + 2, 0); // 再读取域名长度和端口
    }
    socks_stream.read_exact(&mut socks_response[10..]).await?;

    println!("Connected to SOCKS proxy and target server");

    // 数据转发
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

            // 加密数据
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

            // 解密数据
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

    // 分割请求行和头部信息
    let mut lines = request_str.lines();
    let request_line = lines.next().ok_or("Invalid HTTP request")?;

    // 解析请求行
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().ok_or("Invalid HTTP request")?;
    let url = parts.next().ok_or("Invalid HTTP request")?;
    let _version = parts.next().ok_or("Invalid HTTP request")?;

    // 提取主机名和端口号
    let (mut host, mut port) = if url.starts_with("http://") {
        extract_host_and_port(&url[7..], 80)?
    } else if url.starts_with("https://") {
        extract_host_and_port(&url[8..], 443)?
    } else {
        (None, 80)
    };

    // 如果请求行中未找到主机名，则查找 Host 头部
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

// 从主机字符串中提取主机名和端口号
fn extract_host_and_port(host: &str, default_port: u16) -> Result<(Option<String>, u16), Box<dyn Error>> {
    let mut host_port = host.split(':');
    let host_name = host_port.next().ok_or("Invalid host format")?;
    let port_str = host_port.next();

    let port = if let Some(port_str) = port_str {
        port_str.parse::<u16>().map_err(|_| "Invalid port number")?
    } else {
        default_port
    };

    // 去掉路径和查询参数
    let host_name = if let Some(pos) = host_name.find('/') {
        &host_name[..pos]
    } else {
        host_name
    };

    Ok((Some(host_name.to_string()), port))
}

// 构造 SOCKS5 协议请求
fn build_socks5_request(target_host: &str, target_port: u16) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut request = vec![0x05, 0x01, 0x00]; // SOCKS5, CONNECT, NO AUTHENTICATION REQUIRED

    if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
        request.push(0x01); // 地址类型: IPv4
        request.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = target_host.parse::<std::net::Ipv6Addr>() {
        request.push(0x04); // 地址类型: IPv6
        request.extend_from_slice(&ip.octets());
    } else {
        request.push(0x03); // 地址类型: 域名
        request.push(target_host.len() as u8);
        request.extend_from_slice(target_host.as_bytes());
    }

    request.extend_from_slice(&target_port.to_be_bytes());
    Ok(request)
}

// 解析域名到 IP 地址
async fn resolve_domain_to_ip(domain: &str) -> Result<String, Box<dyn Error>> {
    // 使用 DNS 解析主机名
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
