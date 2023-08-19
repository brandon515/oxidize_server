use tokio::net::TcpListener;
use tokio::sync::Mutex;

use std::path::Path;
use std::sync::Arc;
use oxidize::{
    crypto::AsymKey,
    chat::User,
};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const SECRET_FILENAME: &str = "./keys/ServerKey";
    const PUBLIC_FILENAME: &str = "./keys/ServerKey.pub";
    const DATABASE_FILENAME: &str = "./keys/users.db";
    const RSA_BITS: usize = 2048;
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
    let addr = "142.93.202.81:10000";
    let listener = TcpListener::bind(addr).await?;
    println!("Server is listening on {}", addr);
    
    loop{
        let (socket, _) = listener.accept().await?;

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
