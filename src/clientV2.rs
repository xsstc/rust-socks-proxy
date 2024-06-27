use futures::join;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::try_join;
use std::net::SocketAddr;

const SOCKS5_PROXY_ADDR: &str = "xx.xx.xx.xx:6969";

pub async fn run_client() -> io::Result<()> {
    // Listen on local port 12345
    let listener = TcpListener::bind("127.0.0.1:12345").await?;

    loop {
        // Accept a new connection
        let (local_socket, _) = listener.accept().await?;

        // Handle the connection
        tokio::spawn(async move {
            if let Err(e) = handle_connection(local_socket).await {
                eprintln!("Error handling connection: {:?}", e);
            }
        });
    }
}

async fn handle_connection(mut local_socket: TcpStream) -> io::Result<()> {
    // Read the client's request to parse the target address and port
    let mut buffer = [0; 1024];
    let n = local_socket.read(&mut buffer).await?;
    let request = &buffer[..n];
    println!("Received request===> {:?}",  String::from_utf8_lossy(request).to_string());

    // Parse the target address and port
    let (target_addr, target_port) = parse_target_info(request)?;
    println!("Target address: {}, target port: {}", target_addr, target_port);

    // Connect to the SOCKS5 proxy server
    let mut sock = TcpStream::connect(SOCKS5_PROXY_ADDR).await?;

    // 1. Authentication method negotiation
    let auth_request = [0x05, 0x01, 0x00];
    sock.write_all(&auth_request).await?;

    let mut auth_response = [0u8; 2];
    sock.read_exact(&mut auth_response).await?;
    if auth_response[1] != 0x00 {
        eprintln!("Unsupported authentication method.");
        return Err(io::Error::new(io::ErrorKind::Other, "Unsupported authentication method"));
    }

    // 2. Send CONNECT request
    let domain_len = target_addr.len() as u8;
    let mut connect_request = vec![0x05, 0x01, 0x00, 0x03, domain_len];
    connect_request.extend_from_slice(target_addr.as_bytes());
    connect_request.extend_from_slice(&target_port.to_be_bytes());
    sock.write_all(&connect_request).await?;

    // 3. Read server response
    let mut connect_response = [0u8; 10];
    sock.read_exact(&mut connect_response).await?;
    if connect_response[1] != 0x00 {
        eprintln!("Failed to connect to the target server.");
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to connect to target server"));
    }

    local_socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;

    // 4. Data forwarding
    let (mut local_reader, mut local_writer) = local_socket.split();
    let (mut remote_reader, mut remote_writer) = sock.split();

    let client_to_socks = async {
        io::copy(&mut local_reader, &mut remote_writer).await?;
        remote_writer.shutdown().await
    };

    let socks_to_client = async {
        io::copy(&mut remote_reader, &mut local_writer).await?;
        local_writer.shutdown().await
    };

    // // Use `select` to handle data forwarding simultaneously
    // select! {
    //     result = client_to_socks => {
    //         if let Err(e) = result {
    //             eprintln!("Error forwarding client to socks: {:?}", e);
    //         }
    //     },
    //     result = socks_to_client => {
    //         if let Err(e) = result {
    //             eprintln!("Error forwarding socks to client: {:?}", e);
    //         }
    //     },
    // }


    if let Err(e) = try_join!(client_to_socks, socks_to_client) {
        eprintln!("Error forwarding data: {:?}", e);
    }

    Ok(())
}

// A simple function to parse target information
fn parse_target_info(request: &[u8]) -> io::Result<(String, u16)> {
    let req = String::from_utf8_lossy(request).to_string();
    let mut lines = req.lines();
    let request_line = lines.next().unwrap();
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().ok_or("Invalid HTTP request");
    let url = parts.next().unwrap();

    // println!("url===>{}", url);
    let (remote_host, remote_port) = if url.starts_with("http://") {
        let url = &url[7..];
        let mut parts = url.split('/');
        let host_port = parts.next().ok_or("Invalid HTTP request");
        let mut host_port_parts = host_port.unwrap().split(':');
        let host = host_port_parts.next().ok_or("Invalid HTTP request");
        let port = host_port_parts.next().unwrap_or("443");
        (host.unwrap().to_string(), port.parse::<u16>().unwrap())
    } else {
        let mut host_and_port = url.split(":");
        let target_addr = host_and_port.next().unwrap().to_string();
        let target_port: u16 = host_and_port
        .next()                  // Get the next part after the address (port part)
        .map_or(443, |port_str|  // If it's None, use 443
            port_str.parse().unwrap_or(443) // If parsing fails, use 443
        );
        (target_addr, target_port)
    };

    // println!("target_addr===>{}, target_port===>{}", remote_host, remote_port);
    Ok((remote_host, remote_port))
}
