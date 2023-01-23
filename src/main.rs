use futures_core::Stream;
use tonic::transport::Server;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use tokio_stream::wrappers::ReceiverStream;

pub mod route{
    tonic::include_proto!("route");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("route_descriptor");
}
use route::route_server::{Route, RouteServer};
use route::{User, Missive, OperationSuccess};

#[derive(Debug)]
struct RouteService;

#[tonic::async_trait]
impl Route for RouteService{
    async fn send_message(&self, message: Request<Missive>) -> Result<Response<OperationSuccess>, Status>{
        let reply = OperationSuccess{
            success: true,
            error: message.into_inner().message,
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

    let rt = RouteService{};

    let svc = RouteServer::new(rt);

    Server::builder()
    .add_service(reflection)
    .add_service(svc)
    .serve(addr).await?;

    Ok(())
}
