"""Mostly lifted from certbot/acme/examples/http01_example.py with some modifications"""
"""Original Copyright (c) Electronic Frontier Foundation and others
Licensed Apache Version 2.0
https://github.com/certbot/certbot/blob/master/LICENSE.txt
"""

from contextlib import contextmanager
from typing import Optional, Tuple

import josepy as jose
from acme import challenges, client, crypto_util, messages, standalone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from ratelimit import limits

DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"

LETSENCRYPT_STAGING_RATE_LIMIT = 300

PERIOD = 10800  # 3 hours

USER_AGENT = "sds-py"

# Account key size
ACC_KEY_BITS = 2048

# Certificate private key size
CERT_PKEY_BITS = 2048

PORT = 80


def new_csr_comp(
    domain_name: str, pkey_pem: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Create certificate signing request."""
    if pkey_pem is None:
        # Create private key.
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=CERT_PKEY_BITS, backend=default_backend()
        )
        pkey_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    print("CSR created")
    csr_pem = crypto_util.make_csr(pkey_pem, [domain_name])
    return pkey_pem, csr_pem


def select_http01_chall(
    order: messages.OrderResource,
) -> messages.ChallengeBody:
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = order.authorizations

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.HTTP01):
                return i

    raise Exception("HTTP-01 challenge was not offered by the CA server.")


@contextmanager
def challenge_server(http_01_resources):
    """Manage standalone server set up and shutdown."""

    # Setting up a fake server that binds at PORT and any address.
    address = ("", PORT)
    try:
        servers = standalone.HTTP01DualNetworkedServers(address, http_01_resources)
        # Start client standalone web server.
        servers.serve_forever()
        yield servers
    finally:
        # Shutdown client web server and unbind from PORT
        servers.shutdown_and_server_close()


def perform_http01(
    client_acme: client.ClientV2,
    challb: messages.ChallengeBody,
    order: messages.OrderResource,
) -> str:
    """Set up standalone webserver and perform HTTP-01 challenge."""

    response, validation = challb.response_and_validation(client_acme.net.key)

    resource = standalone.HTTP01RequestHandler.HTTP01Resource(
        chall=challb.chall, response=response, validation=validation
    )

    with challenge_server({resource}):
        # Let the CA server know that we are ready for the challenge.
        client_acme.answer_challenge(challb, response)

        # Wait for challenge status and then issue a certificate.
        # It is possible to set a deadline time.
        finalized_order = client_acme.poll_and_finalize(order)

    return finalized_order.fullchain_pem


def setup_client(email: str = "sds-py-test@example.com") -> client.ClientV2:
    # Create account key
    acc_key = jose.JWKRSA(
        key=rsa.generate_private_key(
            public_exponent=65537, key_size=ACC_KEY_BITS, backend=default_backend()
        )
    )

    # Register account and accept TOS
    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = messages.Directory.from_json(net.get(DIRECTORY_URL).json())
    client_acme = client.ClientV2(directory, net=net)

    # Terms of Service URL is in client_acme.directory.meta.terms_of_service
    # Registration Resource: regr
    # Creates account with contact information.
    client_acme.net.account = client_acme.new_account(
        messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True)
    )
    return client_acme


@limits(calls=LETSENCRYPT_STAGING_RATE_LIMIT, period=PERIOD)
def http01(domain: str, email: str, client_acme: client.ClientV2 = None):
    # Create domain private key and CSR
    pkey_pem, csr_pem = new_csr_comp(domain)

    if not client_acme:
        client_acme = setup_client(email=email)
    print(client_acme.net.account)
    # Issue certificate
    order = client_acme.new_order(csr_pem)
    print(order)

    # Select HTTP-01 within offered challenges by the CA server
    challb = select_http01_chall(order)

    # The certificate is ready to be used in the variable "fullchain_pem".
    fullchain_pem = perform_http01(client_acme, challb, order)
    print(fullchain_pem)

    return fullchain_pem, pkey_pem
