import argparse
import logging
from concurrent import futures
from typing import Iterable

import envoy.service.secret.v3.sds_pb2 as sds_pb2
import grpc
from envoy.config.core.v3.base_pb2 import DataSource
from envoy.extensions.transport_sockets.tls.v3.common_pb2 import (
    TlsCertificate,
    CertificateValidationContext,
)
from envoy.extensions.transport_sockets.tls.v3.secret_pb2 import _SECRET, Secret
from envoy.service.discovery.v3.discovery_pb2 import (
    DiscoveryRequest,
    DiscoveryResponse,
    _DISCOVERYRESPONSE,
)
from envoy.service.secret.v3.sds_pb2_grpc import (
    SecretDiscoveryServiceServicer,
    add_SecretDiscoveryServiceServicer_to_server,
)
from google.protobuf import json_format
from google.protobuf.any_pb2 import Any
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

from acme_solver import http01
from test_constants import CERT, PRIVATEKEY, ROOTCERT

logger = logging.getLogger()
console_handler = logging.StreamHandler()
formatter = logging.Formatter(fmt="%(asctime)s: %(levelname)-8s %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

_LISTEN_HOST = "0.0.0.0"

_THREAD_POOL_SIZE = 256
TYPE_PREFIX = "type.googleapis.com/"


class SecretDiscoveryService(SecretDiscoveryServiceServicer):
    def __init__(self, email: str = None):
        self._email = email

    def StreamSecrets(
        self,
        request_iterator: Iterable[DiscoveryRequest],
        context,
    ) -> DiscoveryResponse:
        for message in request_iterator:
            logging.info(f"Received request for {message.resource_names}")

            # Perform HTTP-01 challenge, get cert
            # certificate, private_key = http01(
            #     domain=message.resource_names, email=self._email
            # )

            if "cert" in message.resource_names:
                resource = Secret(
                    name="cert",
                    tls_certificate=TlsCertificate(
                        certificate_chain=DataSource(inline_string=CERT),
                        private_key=DataSource(inline_string=PRIVATEKEY),
                    ),
                )
            elif "validation_context" in message.resource_names:
                resource = Secret(
                    name="validation_context",
                    validation_context=CertificateValidationContext(
                        trusted_ca=DataSource(inline_string=ROOTCERT)
                    ),
                )
            response = DiscoveryResponse(
                type_url=f"{TYPE_PREFIX}{_SECRET.full_name}",
                version_info="0",
            )
            secret = Any()
            secret.Pack(resource)
            response.resources.append(secret)
            yield response


def _configure_secret_server(server: grpc.Server, port: int, email: str) -> None:
    add_SecretDiscoveryServiceServicer_to_server(
        SecretDiscoveryService(email=email), server
    )
    listen_address = f"{_LISTEN_HOST}:{port}"
    server.add_insecure_port(listen_address)


def _configure_maintenance_server(server: grpc.Server, port: int) -> None:
    listen_address = f"{_LISTEN_HOST}:{port}"
    server.add_insecure_port(listen_address)

    # Create a health check servicer. We use the non-blocking implementation
    # to avoid thread starvation.
    health_servicer = health.HealthServicer(
        experimental_non_blocking=True,
        experimental_thread_pool=futures.ThreadPoolExecutor(
            max_workers=_THREAD_POOL_SIZE
        ),
    )

    # Create a tuple of all of the services we want to export via reflection.
    services = tuple(
        service.full_name for service in sds_pb2.DESCRIPTOR.services_by_name.values()
    ) + (reflection.SERVICE_NAME, health.SERVICE_NAME)

    # Mark all services as healthy.
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    for service in services:
        health_servicer.set(service, health_pb2.HealthCheckResponse.SERVING)
    reflection.enable_server_reflection(services, server)


def serve(port: int, email: str) -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=_THREAD_POOL_SIZE))
    _configure_secret_server(server, port, email)
    _configure_maintenance_server(server, port)
    server.start()
    logger.info("Secret server listening on port %d", port)
    logger.info("Maintenance server listening on port %d", port)
    server.wait_for_termination()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple certificate server")
    parser.add_argument(
        "port", default=50051, type=int, nargs="?", help="The port on which to listen."
    )
    parser.add_argument(
        "--email",
        type=str,
        default="sds-py-test@example.com",
        help="Email to be used for the LetsEncrypt account.",
    )

    args = parser.parse_args()
    logging.basicConfig()
    logger.setLevel(logging.INFO)
    serve(args.port, args.email)
