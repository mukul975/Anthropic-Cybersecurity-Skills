# API Reference: Implementing mTLS for Zero Trust Services

## cryptography (Certificate Generation)

```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Generate RSA key
key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

# Build CA certificate
cert = (x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256()))

# Save PEM
key_pem = key.private_bytes(serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
cert_pem = cert.public_bytes(serialization.Encoding.PEM)
```

## ssl Module (mTLS Connection)

```python
import ssl, socket

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_cert_chain("client.pem", "client-key.pem")
context.load_verify_locations("ca.pem")
context.verify_mode = ssl.CERT_REQUIRED

with socket.create_connection(("host", 443)) as sock:
    with context.wrap_socket(sock, server_hostname="host") as ssock:
        peer = ssock.getpeercert()
        print(ssock.version(), peer["subject"])
```

## cert-manager (Kubernetes)

```bash
# Install cert-manager
helm install cert-manager jetstack/cert-manager --set installCRDs=true

# Create ClusterIssuer for internal CA
kubectl apply -f cluster-issuer.yaml
```

### References

- cryptography: https://cryptography.io/en/latest/
- Python ssl: https://docs.python.org/3/library/ssl.html
- cert-manager: https://cert-manager.io/docs/
