use futures_core::Stream;
use tonic::transport::Server;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use tokio_stream::wrappers::ReceiverStream;

pub mod oxidize_proto{
    tonic::include_proto!("oxidize_proto");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("chat_descriptor");
}
use oxidize_proto::chat_server::{Chat, ChatServer};
use oxidize_proto::{User, Missive, OperationSuccess, Test};

#[derive(Debug)]
struct ChatService;

#[tonic::async_trait]
impl Chat for ChatService{
    async fn send_message(&self, message: Request<Missive>) -> Result<Response<OperationSuccess>, Status>{
        let reply = OperationSuccess{
            success: true,
            error: message.into_inner().message,
        };
        Ok(Response::new(reply))
    }

    async fn test_run(&self, tester: Request<Test>) -> Result<Response<Test>, Status>{
        let reply = Test{
            msg: tester.into_inner().msg,
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(route::FILE_DESCRIPTOR_SET)
        .build()
        .unwrap();
    let addr = "142.93.202.81:10000".parse().unwrap();

    println!("Listening on {}", addr);

    let rt = ChatService{};

    let svc = ChatServer::new(rt);

    Server::builder()
    .add_service(reflection)
    .add_service(svc)
    .serve(addr).await?;

    Ok(())
}
