import argparse
from asgiref.wsgi import WsgiToAsgi
from envoy.config.core.v3.base_pb2 import DataSource
from envoy.extensions.transport_sockets.tls.v3.common_pb2 import TlsCertificate
from envoy.extensions.transport_sockets.tls.v3.secret_pb2 import Secret
from envoy.service.discovery.v3.discovery_pb2 import DiscoveryResponse
from flask import Flask, request
from google.protobuf import json_format
from google.protobuf.any_pb2 import Any

from acme_solver import http01
from test_constants import CERT, PRIVATEKEY, ROOTCERT

flask_app = Flask(__name__)

TYPE_SDS = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"


@flask_app.post("/v3/discovery:secrets")
def secrets():
    discovery_req = request.get_json()
    domain_name = discovery_req["resource_names"][0]  # Single TLS cert per request

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

    if "root" in discovery_req["resource_names"]:
        resource = (
            Secret(
                name="root",
                validation_context=TlsCertificate(
                    certificate_chain=DataSource(inline_string=ROOTCERT)
                ),
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
        resource = None

    response = DiscoveryResponse()
    secret = Any()
    secret.Pack(resource, type_url=TYPE_SDS)
    response.resources.append(secret)

    return json_format.MessageToJson(response)


asgi_app = WsgiToAsgi(flask_app)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple REST certificate server")
    parser.add_argument(
        "port", default=50051, type=int, nargs="?", help="The port on which to listen."
    )
    args = parser.parse_args()
    flask_app.run(port=args.port)
