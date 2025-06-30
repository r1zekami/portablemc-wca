import ssl
import socket
import argparse

parser = argparse.ArgumentParser(description='Extract SSL certificate from a host and save it as PEM file.')
parser.add_argument('--host', required=True, help='Domain or IP address of the host')
parser.add_argument('--port', required=True, type=int, help='Port number')
args = parser.parse_args()

host = args.host
port = args.port

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((host, port)) as sock:
    with context.wrap_socket(sock, server_hostname=host) as ssock:
        cert = ssock.getpeercert(binary_form=True)
        pem_cert = ssl.DER_cert_to_PEM_cert(cert)
        
        with open(f"{host}-auth-serv-cert.pem", 'w') as f:
            f.write(pem_cert)
        
        print(f"Success")

