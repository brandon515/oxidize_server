use der::DateTime;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use base64::{
    Engine as _, 
    engine::general_purpose, 
};

use std::{
    path::Path, 
    time::SystemTime
};
use std::sync::Arc;
use oxidize::{
    crypto::AsymKey,
    chat::User,
};
use local_ip_address::local_ip;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const SECRET_FILENAME: &str = "./keys/ServerKey";
    const PUBLIC_FILENAME: &str = "./keys/ServerKey.pub";
    const DATABASE_FILENAME: &str = "./keys/users.db";
    const RSA_BITS: usize = 2048;
    const PORT: &str = "10000";
    let ip = local_ip().unwrap();
    let asym_encryption = match Path::new(&SECRET_FILENAME).exists(){
        true => {
            let password = rpassword::prompt_password("Password: ").unwrap();
            match AsymKey::from_files(PUBLIC_FILENAME, SECRET_FILENAME, password){
                Ok(r) => r,
                Err(e) => {
                    println!("Error loading private keys\nError: {:?}", e);
                    panic!();
                },
            }
        },
        false => {
            println!("Private key file not found, creating new ones.");
            println!("***************************************");
            println!("*  THIS WILL OVERWRITE ANY EXISTING   *");
            println!("*  PUBLIC KEY FILES IN THE FOLDER     *");
            println!("***************************************");
            let mut password = rpassword::prompt_password("New Password: ").unwrap();
            let mut confirm_password = rpassword::prompt_password("Confirm Password: ").unwrap();
            while password != confirm_password {
                println!("Passwords do not match");
                password = rpassword::prompt_password("New Password: ").unwrap();
                confirm_password = rpassword::prompt_password("Confirm Password: ").unwrap();
            }
            let key_new = AsymKey::from_rng(RSA_BITS).unwrap();
            key_new.to_files(PUBLIC_FILENAME, SECRET_FILENAME, password).unwrap();
            key_new
        },
    };
    let asym_key = Arc::new(Mutex::new(asym_encryption));
    let mut addr = ip.to_string();
    let mut invite_string = addr.clone();
    invite_string.push_str("\n");
    invite_string.push_str(PORT);
    invite_string.push_str("\n");
    addr.push_str(":");
    addr.push_str(PORT);
    let listener = TcpListener::bind(addr).await?;
    let pub_pem = asym_key.lock().await.get_public_key().unwrap();
    invite_string.push_str(&pub_pem);
    let invite_base64 = general_purpose::STANDARD.encode(invite_string.as_bytes());
    println!("Server is listening on {:?}", listener.local_addr().unwrap());
    println!("Invite String is {}", invite_base64);
    
    loop{
        let (socket, addr) = listener.accept().await?;
        let dt = DateTime::from_system_time(SystemTime::now()).unwrap();
        println!("Connection Establish with {:?} at {}", addr, dt.to_string());

        let new_key = Arc::clone(&asym_key);
        tokio::spawn(async move {
            let mut user = User::new(socket, new_key, DATABASE_FILENAME.to_string());

            user.handshake().await.unwrap();

            loop{
                /*let n = match socket.read(&mut buf).await{
                    Ok(n) if n == 0 => return,
                    Ok(n) => n,
                    Err(e) => {
                        println!("Failure: {:?}", e);
                        return;
                    }
                };

                if let Err(e) = socket.write_all(&buf[0..n]).await{
                    println!("Failure: {:?}", e);
                    return;
                }*/
            }
        });
    }
}
