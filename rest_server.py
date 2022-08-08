import argparse
import logging
from asgiref.wsgi import WsgiToAsgi
from envoy.config.core.v3.base_pb2 import DataSource
from envoy.extensions.transport_sockets.tls.v3.common_pb2 import (
    TlsCertificate,
    CertificateValidationContext,
)
from envoy.extensions.transport_sockets.tls.v3.secret_pb2 import Secret
from envoy.service.discovery.v3.discovery_pb2 import (
    DiscoveryResponse,
    _DISCOVERYRESPONSE,
)
from flask import Flask, request
from google.protobuf import json_format
from google.protobuf.any_pb2 import Any

from acme_solver import http01
from test_constants import CERT, PRIVATEKEY, ROOTCERT

TYPE_SECRET = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
TYPE_PREFIX = "type.googleapis.com/"

flask_app = Flask(__name__)


logger = logging.getLogger()
console_handler = logging.StreamHandler()
formatter = logging.Formatter(fmt="%(asctime)s: %(levelname)-8s %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


@flask_app.post("/v3/discovery:secrets")
def secrets():
    discovery_req = request.get_json()
    domain_name = discovery_req["resource_names"][0]  # Single TLS cert per request
    logging.info(f"Received request for {domain_name}")

    # Perform HTTP-01 challenge, get cert
    # certificate, private_key = http01(domain=domain_name)

    # Build response body
    # resource = Secret(
    #     name=domain_name,
    #     tls_certificate=TlsCertificate(
    #         certificate_chain=DataSource(inline_string=certificate),
    #         private_key=DataSource(inline_bytes=private_key),
    #     ),
    # )

    if "validation_context" in discovery_req["resource_names"]:
        resource = Secret(
            name="validation_context",
            validation_context=CertificateValidationContext(
                trusted_ca=DataSource(inline_string=ROOTCERT)
            ),
        )
    elif "cert" in discovery_req["resource_names"]:
        resource = Secret(
            name="cert",
            tls_certificate=TlsCertificate(
                certificate_chain=DataSource(inline_string=CERT),
                private_key=DataSource(inline_string=PRIVATEKEY),
            ),
        )
    else:
        return "Not found", 404

    response = DiscoveryResponse(type_url=f"{TYPE_SECRET}", version_info="0")
    secret = Any()
    secret.Pack(resource)
    response.resources.append(secret)

    return json_format.MessageToJson(response)


asgi_app = WsgiToAsgi(flask_app)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple REST certificate server")
    parser.add_argument(
        "port", default=50051, type=int, nargs="?", help="The port on which to listen."
    )
    args = parser.parse_args()
    logging.basicConfig()
    logger.setLevel(logging.INFO)
    flask_app.run(port=args.port)
