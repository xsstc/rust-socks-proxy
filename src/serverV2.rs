use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::lookup_host;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::try_join;

pub async fn run_server() -> io::Result<()> {
    // Listen on a specific port
    let listener = TcpListener::bind("0.0.0.0:6969").await?;

    loop {
        // Accept a new connection
        let (mut socket, _) = listener.accept().await?;

        // Handle the connection
        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut socket).await {
                eprintln!("Error handling client: {:?}", e);
            }
        });
    }
}

async fn handle_client(socket: &mut TcpStream) -> io::Result<()> {
    // Read SOCKS5 version and authentication methods
    let mut buffer = [0u8; 2];
    socket.read_exact(&mut buffer).await?;
    if buffer[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid SOCKS version"));
    }

    // Read the supported authentication methods from the client
    let n_methods = buffer[1] as usize;
    let mut methods = vec![0u8; n_methods];
    socket.read_exact(&mut methods).await?;

    // No authentication required
    let response = [0x05, 0x00];
    socket.write_all(&response).await?;

    // Read the client's request
    let mut request = [0u8; 4];
    socket.read_exact(&mut request).await?;
    // println!("Request ===> {:?}", request);
    if request[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid SOCKS version"));
    }

    // Only support CONNECT requests
    if request[1] != 0x01 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported command"));
    }

    // Determine address type
    let addr_type = request[3];
    let target_addr = match addr_type {
        0x01 => {
            // IPv4 address
            let mut ipv4 = [0u8; 4];
            socket.read_exact(&mut ipv4).await?;
            IpAddr::V4(Ipv4Addr::new(ipv4[0], ipv4[1], ipv4[2], ipv4[3]))
        }
        0x03 => {
            // Domain name
            let mut domain_len = [0u8; 1];
            socket.read_exact(&mut domain_len).await?;
            let domain_len = domain_len[0] as usize;
            // println!("Domain len ===> {}", domain_len);
            if domain_len == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Domain length is zero"));
            }

            let mut domain = vec![0u8; domain_len];
            socket.read_exact(&mut domain).await?;
            // println!("Domain bytes ===> {:?}", domain);

            // Try to convert to string
            match std::str::from_utf8(&domain) {
                Ok(domain_str) => {
                    println!("Domain ===> {}", domain_str);

                    // Check if the domain contains invalid characters
                    if domain_str.contains('\0') {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Domain name contains unexpected NUL byte"));
                    }

                    // DNS resolution
                    let addr_iter = lookup_host((domain_str, 0)).await?;
                    let ip = addr_iter
                        .filter(|addr| matches!(addr, SocketAddr::V4(_)))
                        .next()
                        .ok_or(io::Error::new(io::ErrorKind::NotFound, "No IP found"))?;
                    ip.ip()
                }
                Err(e) => {
                    eprintln!("Invalid UTF-8 sequence: {:?}", e);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid domain name"));
                }
            }
        }
        0x04 => {
            // IPv6 address
            let mut ipv6 = [0u8; 16];
            socket.read_exact(&mut ipv6).await?;
            IpAddr::V6(Ipv6Addr::new(
                ((ipv6[0] as u16) << 8) | (ipv6[1] as u16),
                ((ipv6[2] as u16) << 8) | (ipv6[3] as u16),
                ((ipv6[4] as u16) << 8) | (ipv6[5] as u16),
                ((ipv6[6] as u16) << 8) | (ipv6[7] as u16),
                ((ipv6[8] as u16) << 8) | (ipv6[9] as u16),
                ((ipv6[10] as u16) << 8) | (ipv6[11] as u16),
                ((ipv6[12] as u16) << 8) | (ipv6[13] as u16),
                ((ipv6[14] as u16) << 8) | (ipv6[15] as u16),
            ))
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported address type")),
    };

    // Read the target port
    let mut port = [0u8; 2];
    socket.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    // Check if the port is valid
    if port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid port number"));
    }

    // Try to connect to the target server
    let target_socket = SocketAddr::new(target_addr, port);
    match TcpStream::connect(target_socket).await {
        Ok(mut remote_socket) => {
            // Send success response
            let success_response = [
                0x05, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,  // BND.ADDR
                0x00, 0x00               // BND.PORT
            ];
            socket.write_all(&success_response).await?;

            // Data forwarding
            let (mut client_reader, mut client_writer) = socket.split();
            let (mut remote_reader, mut remote_writer) = remote_socket.split();

            let client_to_remote = async {
                io::copy(&mut client_reader, &mut remote_writer).await?;
                remote_writer.shutdown().await
            };

            let remote_to_client = async {
                io::copy(&mut remote_reader, &mut client_writer).await?;
                client_writer.shutdown().await
            };

            // // Use select! to handle data forwarding simultaneously
            // tokio::select! {
            //     result = client_to_remote => {
            //         if let Err(e) = result {
            //             eprintln!("Error forwarding client to remote: {:?}", e);
            //         }
            //     },
            //     result = remote_to_client => {
            //         if let Err(e) = result {
            //             eprintln!("Error forwarding remote to client: {:?}", e);
            //         }
            //     },
            // }

            if let Err(e) = try_join!(client_to_remote, remote_to_client) {
                eprintln!("Error forwarding data: {:?}", e);
            }


        }
        Err(e) => {
            eprintln!("Failed to connect to target server: {:?}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to connect to target server"));
        }
    }

    Ok(())
}
