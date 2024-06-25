mod clientV2;
mod serverV2;
mod crypto;

use tokio::io;
#[tokio::main]
async fn main() -> Result<(), io::Error>{
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "client" => clientV2::run_client().await,
            "server" => serverV2::run_server().await,
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Usage: [client|server]")) 
        }
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "Usage: [client|server]")) 
 
    }
}
