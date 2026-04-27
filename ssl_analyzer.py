import ssl
import socket
from datetime import datetime

def analyze(domain):
    context = ssl.create_default_context()

    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()

            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])

            print("\n=== Certificate Info ===")
            print("Domain:", subject.get('commonName'))
            print("Issuer:", issuer.get('commonName'))

            expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            print("Expiry:", expiry)

            if expiry < datetime.utcnow():
                print("⚠️ Expired")
            else:
                print("✅ Valid")

if __name__ == "__main__":
    domain = input("Enter domain: ")
    analyze(domain)
