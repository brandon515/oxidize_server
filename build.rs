use std::{
    env,
    path::PathBuf,
};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("chat_descriptor.bin"))
        .compile(&["oxidize_protos/chat.proto"], &["proto"])
        .unwrap();
    
    tonic_build::compile_protos("oxidize_protos/chat.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
}