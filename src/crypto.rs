use aes_gcm::{
    aead::{
        KeyInit,
        Aead,
        generic_array::GenericArray,
        self,
    },
    Nonce, 
    Aes256Gcm, AeadCore, aes::Aes256,
};
use rand_core::SeedableRng;
use rsa::{
    PublicKey,
    RsaPublicKey,
    RsaPrivateKey,
    Oaep,
    sha2::Sha256, pkcs8::DecodePublicKey,
    pkcs8::{
        spki, 
        DecodePrivateKey, 
        EncodePublicKey, 
        EncodePrivateKey,
        LineEnding,
    },
    pkcs1v15::Pkcs1v15Sign,
};
use rand_chacha::ChaCha20Rng;
use std::{
    fs::OpenOptions,
    io::{
        BufReader,
        Read,
    },
};
use serde::{
    Serialize,
    Deserialize,
};
#[derive(Debug)]
pub enum Error{
    PubKeyError(spki::Error),
    IOError(std::io::Error),
    PrivDerError(rsa::pkcs8::Error),
    PrivKeyError(rsa::errors::Error),
    EncryptionError(rsa::errors::Error),
    DecryptionError(rsa::errors::Error),
    SigningError(rsa::errors::Error),
    VerificationError(rsa::errors::Error),
    PrivKeyMissing(),
    Other(String),
}
pub struct AsymKey{
    priv_key: Option<RsaPrivateKey>,
    pub_key: RsaPublicKey,
}

impl AsymKey{
    pub fn get_public_key(&self) -> Result<String, Error>{
        match self.pub_key.to_public_key_pem(LineEnding::default()){
            Ok(r) => Ok(r),
            Err(e) => Err(Error::PubKeyError(e)),
        }
    }
    pub fn sign(&self, data: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let priv_key = match &self.priv_key{
            Some(r) => r,
            None => {
                return Err(Error::PrivKeyMissing());
            }
        };
        let mut csprng = ChaCha20Rng::from_entropy();
        let padding = Pkcs1v15Sign::new::<Sha256>();
        match priv_key.sign_with_rng(&mut csprng, padding, data.as_slice()){
            Ok(r) => Ok(r),
            Err(e) => Err(Error::SigningError(e)),
        }
    }
    pub fn verify(&self, data: &Vec<u8>, signature: &Vec<u8>) -> Result<bool, Error>{
        let padding = Pkcs1v15Sign::new::<Sha256>();
        match self.pub_key.verify(padding, data.as_slice(), signature.as_slice()){
            Ok(_) => Ok(true),
            Err(rsa::errors::Error::Verification) => Ok(false),
            Err(e) => Err(Error::VerificationError(e)), 
        }
    }
    pub fn encrypt(&self, data: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut csprng = ChaCha20Rng::from_entropy();
        let padding = Oaep::new::<rsa::sha2::Sha256>();
        match self.pub_key.encrypt(&mut csprng, padding, data.as_slice()){
            Ok(r) => Ok(r),
            Err(e) => Err(Error::EncryptionError(e))
        }
    }
    pub fn decrypt(&self, data: &Vec<u8>) -> Result<Vec<u8>, Error>{
        let priv_key = match &self.priv_key{
            Some(r) => r,
            None => {
                return Err(Error::PrivKeyMissing());
            }
        };
        let padding = Oaep::new::<rsa::sha2::Sha256>();
        match priv_key.decrypt(padding, data.as_slice()){
            Ok(r) => Ok(r),
            Err(e) => Err(Error::DecryptionError(e)),
        }
    }
    pub fn from_rng(rsa_bits: usize) -> Result<Self, Error>{
        let mut csprng = ChaCha20Rng::from_entropy();
        let priv_key_new = match RsaPrivateKey::new(&mut csprng, rsa_bits){
            Ok(r) => r,
            Err(e) => {
                return Err(Error::PrivKeyError(e));
            }
        };
        let pub_key_new = RsaPublicKey::from(&priv_key_new);
        Ok(AsymKey { 
            priv_key: Some(priv_key_new), 
            pub_key: pub_key_new,
        })
    }
    pub fn to_files(&self, pub_key_filepath: &str, priv_key_filepath: &str, password: String) -> Result<(), Error> {
        let priv_key = match &self.priv_key{
            Some(r) => r,
            None => {
                return Err(Error::PrivKeyMissing());
            }
        };
        let _ = match self.pub_key.write_public_key_pem_file(pub_key_filepath, LineEnding::default()){
            Err(e) => {
                return Err(Error::PubKeyError(e));
            },
            Ok(_) => {},
        };
        let mut csprng = ChaCha20Rng::from_entropy();
        let priv_key_doc = match priv_key.to_pkcs8_encrypted_der(&mut csprng, password){
            Ok(r) => r,
            Err(e) => {
                return Err(Error::PrivDerError(e));
            },
        };
        match priv_key_doc.write_der_file(priv_key_filepath){
            Ok(_) => Ok(()),
            Err(e) => {
                return Err(Error::PrivDerError(rsa::pkcs8::Error::Asn1(e)));
            }
        }
    }
    pub fn from_files(pub_key_filepath: &str, priv_key_filepath: &str, password: String) -> Result<Self, Error>{
        let pub_key_new = match RsaPublicKey::read_public_key_pem_file(pub_key_filepath){
            Ok(r) => r,
            Err(e) => {
                return Err(Error::PubKeyError(e));
            },
        };
        let priv_key_file = match OpenOptions::new().read(true).open(priv_key_filepath) {
            Ok(f) => f,
            Err(e) => {
                return Err(Error::IOError(e));
            },
        };
        let mut priv_key_reader = BufReader::new(priv_key_file);
        let mut priv_key_bytes = Vec::new();
        priv_key_reader.read_to_end(&mut priv_key_bytes).unwrap();
        let priv_key_new = match RsaPrivateKey::from_pkcs8_encrypted_der(priv_key_bytes.as_slice(), password){
            Ok(r) => r,
            Err(e) => {
                return Err(Error::PrivDerError(e));
            }
        };
        Ok(AsymKey{
            priv_key: Some(priv_key_new),
            pub_key: pub_key_new,
        })
    }
    pub fn from_public_key(pub_key: Vec<u8>) -> Self{
        let pem_data = String::from_utf8(pub_key).unwrap();
        AsymKey { 
            priv_key: None, 
            pub_key: RsaPublicKey::from_public_key_pem(&pem_data).unwrap(),
        }   
    }
}

#[derive(Serialize, Deserialize)]
pub struct SymEncryptedMsg{
    pub msg: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub struct SymKey{
    cipher: Aes256Gcm,
    pub key: Vec<u8>,
}

impl SymKey{
    pub fn from_rng() -> Self{
        let csprng = ChaCha20Rng::from_entropy();
        let key_new = Aes256Gcm::generate_key(csprng).to_vec();
        SymKey{
            cipher: Aes256Gcm::new(GenericArray::from_slice(&key_new)),
            key: key_new,
        }
    }

    pub fn from_key(existing_key: Vec<u8>) -> Self{
        SymKey { 
            cipher: Aes256Gcm::new(GenericArray::from_slice(&existing_key)), 
            key: existing_key,
        }
    }

    pub fn encrypt(&self, data: &Vec<u8>) -> Result<SymEncryptedMsg, aead::Error>{
        let csprng = ChaCha20Rng::from_entropy();
        let nonce_new = Aes256Gcm::generate_nonce(csprng);
        let msg_new = self.cipher.encrypt(&nonce_new, data.as_ref())?;
        Ok(SymEncryptedMsg { 
            msg: msg_new, 
            nonce: nonce_new.to_vec(), 
        })
    }

    pub fn decrypt(&self, en_msg: &SymEncryptedMsg) -> Result<Vec<u8>, aead::Error>{
        let nonce = GenericArray::from_slice(en_msg.nonce.as_ref());
        self.cipher.decrypt(nonce, en_msg.msg.as_ref())
    }
}