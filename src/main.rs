use tokio::net::TcpListener;
use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};

use std::path::Path;
use oxidize::crypto::{
    AsymKey,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const SECRET_FILENAME: &str = "./keys/ServerKey";
    const PUBLIC_FILENAME: &str = "./keys/ServerKey.pub";
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
            println!("Key files not found, creating new ones.");
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
            let key_new = AsymKey::from_rng().unwrap();
            key_new.to_files(PUBLIC_FILENAME, SECRET_FILENAME, password).unwrap();
            key_new
        },
    };
    let msg = b"tester testing test".to_vec();

    let encrypted_msg = asym_encryption.encrypt(&msg).unwrap();
    if msg == encrypted_msg{
        panic!("Public key failed to encrypt");
    }

    let decrypted_msg = asym_encryption.decrypt(&encrypted_msg).unwrap();
    if msg != decrypted_msg{
        panic!("Private key failed to decrypt");
    }

    let addr = "142.93.202.81:10000";
    let listener = TcpListener::bind(addr).await?;
    println!("Server is listening on {}", addr);
    /*loop{
        println!("herro");
    }*/
    
    loop{
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = [0; 1024];

            loop{
                let n = match socket.read(&mut buf).await{
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
                }
            }
        });
    }
}
