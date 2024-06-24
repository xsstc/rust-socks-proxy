use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;

const SERVER_PORT: u16 = 6969;
const KEY: &[u8] = b"01234567890123456789012345678901"; 

async fn handle_server(mut server_stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = [0; 1024];

    // 读取并解析SOCKS5握手
    server_stream.read_exact(&mut buf[0..2]).await?;
    let nmethods = buf[1] as usize;
    server_stream.read_exact(&mut buf[0..nmethods]).await?;

    // 响应选择不需要认证
    server_stream.write_all(&[0x05, 0x00]).await?;

    // 读取客户端请求
    server_stream.read_exact(&mut buf[0..4]).await?;

    let atyp = buf[3];
    println!("Client requested connection ====>{}", atyp);
    let target_addr = match atyp {
        0x01 => { // IPv4
            server_stream.read_exact(&mut buf[0..6]).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            format!("{}:{}", ip, port)
        }
        0x03 => { // 域名
            server_stream.read_exact(&mut buf[0..1]).await?;
            let len = buf[0] as usize;
            server_stream.read_exact(&mut buf[0..len + 2]).await?;
            let domain = std::str::from_utf8(&buf[0..len])?.to_string();
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            format!("{}:{}", domain, port)
        }
        0x04 => { // IPv6
            server_stream.read_exact(&mut buf[0..18]).await?;
            let ip = std::net::Ipv6Addr::new(
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
                u16::from_be_bytes([buf[4], buf[5]]),
                u16::from_be_bytes([buf[6], buf[7]]),
                u16::from_be_bytes([buf[8], buf[9]]),
                u16::from_be_bytes([buf[10], buf[11]]),
                u16::from_be_bytes([buf[12], buf[13]]),
                u16::from_be_bytes([buf[14], buf[15]]),
            );
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            format!("[{}]:{}", ip, port)
        }
        _ => return Err("Unsupported address type".into()),
    };

    println!("Connecting to target address: {}", target_addr);

    // 连接目标服务器
    let target_stream = match TcpStream::connect(&target_addr).await {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("Failed to connect to {}: {:?}", target_addr, err);
            return Err(err.into());
        }
    };

    // 向客户端发送成功响应
    let reply = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    server_stream.write_all(&reply).await?;

    // 代理数据转发
    let (mut server_read, mut server_write) = server_stream.into_split();
    let (mut target_read, mut target_write) = target_stream.into_split();

    tokio::spawn(async move {
        let mut buffer = [0; 1024];
        loop {
            let n = match target_read.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error reading from target: {:?}", e);
                    break;
                }
            };
            if n == 0 {
                break;
            }
            println!("Sending data to client: {}", String::from_utf8_lossy(&buffer[..n]));
            let encrypted_data = crate::crypto::encrypt(&buffer[..n], KEY).expect("Failed to encrypt data");
            if server_write.write_all(&encrypted_data).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let mut buffer = [0; 1024];
        loop {
            let n = match server_read.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error reading from server: {:?}", e);
                    break;
                }
            };
            if n == 0 {
                break;
            }
            let decrypted_data = crate::crypto::decrypt(&buffer[..n], KEY).expect("Failed to decrypt data");
            println!("Received data from client: {}", String::from_utf8_lossy(&decrypted_data));
            
            if target_write.write_all(&decrypted_data).await.is_err() {
                break;
            }
        }
    });

    Ok(())
}

pub async fn run_server() -> std::io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", SERVER_PORT)).await?;
    println!("Server listening on port {}", SERVER_PORT);

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("Accepted connection from {:?}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_server(stream).await {
                eprintln!("Failed to handle server: {:?}", e);
            }
        });
    }
}
