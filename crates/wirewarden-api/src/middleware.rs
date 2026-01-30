use std::future::{Future, Ready, ready};
use std::pin::Pin;

use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::body::BodySize;
use tracing::info;

pub struct RequestLogger;

impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = RequestLoggerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLoggerMiddleware { service }))
    }
}

pub struct RequestLoggerMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestLoggerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().clone();
        let uri = req.uri().to_string();
        let remote_ip = req
            .connection_info()
            .peer_addr()
            .unwrap_or("unknown")
            .to_owned();
        let body_size = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        let start = std::time::Instant::now();
        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            let elapsed = start.elapsed();
            let status = res.status().as_u16();
            let response_size = match res.response().body().size() {
                BodySize::Sized(n) => n,
                _ => 0,
            };

            info!(
                remote_ip = %remote_ip,
                method = %method,
                uri = %uri,
                status = status,
                body_size = body_size,
                response_size = response_size,
                time_ms = elapsed.as_millis() as u64,
                "request"
            );

            Ok(res)
        })
    }
}
