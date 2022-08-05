# Simple Python SDS protocol implementation

## Usage

`pip install -r requirements.txt`

REST server:
`hypercorn -b 127.0.0.1:50051 rest_server:asgi_app`

GRPC server:
`python3 grpc_server.py <PORT>`
