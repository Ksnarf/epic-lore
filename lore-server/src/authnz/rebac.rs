// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::OnceLock;

use lore_base::lore_spawn_net;
use lore_proto::RebacApiClient as RebacApiGrpcClient;
use lore_proto::rebac::CreateResourceRequest;
use lore_proto::rebac::CreateResourceResponse;
use lore_proto::rebac::DeleteResourceRequest;
use lore_proto::rebac::DeleteResourceResponse;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::LabelArray;
use lore_telemetry::METRICS_OPERATION_LATENCY_METRIC_NAME;
use lore_telemetry::timed;
use lore_telemetry::timer::TimedResult;
use lore_transport::grpc::CorrelationInterceptor;
use lore_transport::grpc::inject_authorization;
use opentelemetry::KeyValue;
use smallvec::SmallVec;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::codegen::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::ClientTlsConfig;

use crate::grpc::ServerResultExt;

pub type RebacApiResult<T> = Result<Response<T>, Status>;

/// Token presented to the rebac service, from `[server.auth]
/// rebac_service_token`. Recorded once during startup because the rebac
/// client is built per request, deep below the point where settings are read.
static SERVICE_TOKEN: OnceLock<String> = OnceLock::new();

/// Records the token the rebac client presents from now on. Called once
/// during server startup; later calls are ignored.
pub fn set_service_token(token: String) {
    let _ = SERVICE_TOKEN.set(token);
}

/// Adds the correlation id like every other client, and the configured
/// service token when there is one.
///
/// `CreateResource` and `DeleteResource` act on this server's behalf rather
/// than the caller's, so the caller's `authorization` is replaced. With no
/// token configured the request goes out exactly as the caller built it.
#[derive(Clone)]
pub struct RebacServiceInterceptor {
    service_token: Option<String>,
}

impl Interceptor for RebacServiceInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let mut request = CorrelationInterceptor.call(request)?;
        if let Some(token) = self.service_token.as_deref() {
            inject_authorization(&mut request, token)?;
        }
        Ok(request)
    }
}

#[async_trait::async_trait]
pub trait RebacApiClient {
    async fn create_resource(
        &mut self,
        request: Request<CreateResourceRequest>,
    ) -> RebacApiResult<CreateResourceResponse>;

    async fn delete_resource(
        &mut self,
        request: Request<DeleteResourceRequest>,
    ) -> RebacApiResult<DeleteResourceResponse>;
}

pub struct RebacClientHelper {
    client: RebacApiGrpcClient<
        InterceptedService<tonic::transport::Channel, RebacServiceInterceptor>,
    >,
}

impl RebacClientHelper {
    async fn new(auth_url: String) -> Result<RebacClientHelper, Status> {
        let mut endpoint = tonic::transport::Endpoint::from_shared(auth_url.clone())
            .warn_map_err(|_| Status::internal("Failed to create rebac endpoint"))?;
        if auth_url.starts_with("https://") {
            endpoint = endpoint
                .tls_config(
                    ClientTlsConfig::new()
                        .assume_http2(true)
                        .with_native_roots(),
                )
                .warn_map_err(|_| Status::internal("Failed to configure TLS for rebac"))?;
        }
        // Connect from net so the hyper/h2 driver tasks this spawns bind there
        // rather than to the core runtime the caller runs on.
        let channel = lore_spawn_net!(async move { endpoint.connect().await })
            .await
            .warn_map_err(|_| Status::internal("rebac connection task failed"))?
            .warn_map_err(|_| Status::internal("Failed to connect to rebac service"))?;
        let interceptor = RebacServiceInterceptor {
            service_token: SERVICE_TOKEN.get().cloned(),
        };
        let client = RebacApiGrpcClient::with_interceptor(channel, interceptor);
        Ok(RebacClientHelper { client })
    }
}

#[async_trait::async_trait]
impl RebacApiClient for RebacClientHelper {
    async fn create_resource(
        &mut self,
        request: Request<CreateResourceRequest>,
    ) -> RebacApiResult<CreateResourceResponse> {
        timed!(
            self.latency_histogram_ms(METRICS_OPERATION_LATENCY_METRIC_NAME),
            &self.get_labels_for_operation_context("create_resource"),
            self.client.create_resource(request).await
        )
        .result
    }

    async fn delete_resource(
        &mut self,
        request: Request<DeleteResourceRequest>,
    ) -> RebacApiResult<DeleteResourceResponse> {
        timed!(
            self.latency_histogram_ms(METRICS_OPERATION_LATENCY_METRIC_NAME),
            &self.get_labels_for_operation_context("delete_resource"),
            self.client.delete_resource(request).await
        )
        .result
    }
}

pub async fn grpc_get_rebac_client(auth_url: String) -> Result<RebacClientHelper, Status> {
    RebacClientHelper::new(auth_url).await
}

impl InstrumentProvider for RebacClientHelper {
    fn namespace(&self) -> &'static str {
        "urc.authnz.rebac"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authnz::common::create_request_with_authorization;

    /// Strips the payload off a request the way `InterceptedService` does
    /// before handing it to the interceptor.
    fn intercept(
        service_token: Option<&str>,
        caller_authorization: Option<String>,
    ) -> Result<Request<()>, Status> {
        let request = create_request_with_authorization((), caller_authorization)?;
        let mut interceptor = RebacServiceInterceptor {
            service_token: service_token.map(str::to_string),
        };
        interceptor.call(request)
    }

    #[test]
    fn sends_the_service_token_when_configured() -> Result<(), Status> {
        let request = intercept(Some("service-secret"), Some("Bearer caller-token".into()))?;

        let authorization = request.metadata().get("authorization").unwrap();
        assert_eq!(authorization.to_str().unwrap(), "Bearer service-secret");

        Ok(())
    }

    #[test]
    fn leaves_the_request_alone_when_no_token_is_configured() -> Result<(), Status> {
        let request = intercept(None, Some("Bearer caller-token".into()))?;

        let authorization = request.metadata().get("authorization").unwrap();
        assert_eq!(authorization.to_str().unwrap(), "Bearer caller-token");

        Ok(())
    }
}
