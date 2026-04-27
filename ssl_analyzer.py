
import ssl
import socket
from datetime import datetime

def get_certificate(hostname):
    context = ssl.create_default_context()

    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            return cert

def analyze_cert(cert):
    print("\n=== Certificate Info ===")

    subject = dict(x[0] for x in cert['subject'])
    issuer = dict(x[0] for x in cert['issuer'])

    print("Domain:", subject.get('commonName'))
    print("Issuer:", issuer.get('commonName'))

    expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    print("Expiry Date:", expiry)

    if expiry < datetime.utcnow():
        print("⚠️ Certificate Expired")
    else:
        print("✅ Certificate Valid")

if __name__ == "__main__":
    domain = input("Enter domain: ")
    cert = get_certificate(domain)
    analyze_cert(cert)
