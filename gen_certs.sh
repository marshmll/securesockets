#!/bin/bash

# Generate CA and Server Certificates
# Usage: ./generate_certs.sh [output_dir] [server_name]

set -e

OUTPUT_DIR=${1:-./certs}
SERVER_NAME=${2:-localhost}

echo "Generating certificates in: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Generate CA private key
echo "1. Generating CA private key..."
openssl genrsa -out "$OUTPUT_DIR/ca.key" 4096

# Generate CA certificate
echo "2. Generating CA certificate..."
openssl req -new -x509 -days 3650 -key "$OUTPUT_DIR/ca.key" -out "$OUTPUT_DIR/ca.crt" \
  -subj "/CN=Test CA/O=Test Organization/C=US"

# Generate server private key
echo "3. Generating server private key..."
openssl genrsa -out "$OUTPUT_DIR/server.key" 2048

# Generate server certificate signing request (CSR)
echo "4. Generating server CSR..."
openssl req -new -key "$OUTPUT_DIR/server.key" -out "$OUTPUT_DIR/server.csr" \
  -subj "/CN=$SERVER_NAME/O=Test Server/C=US"

# Create certificate extensions file
echo "5. Creating certificate extensions file..."
cat > "$OUTPUT_DIR/server.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVER_NAME
DNS.2 = $SERVER_NAME.local
IP.1 = 127.0.0.1
EOF

# Sign the server certificate with the CA
echo "6. Signing server certificate with CA..."
openssl x509 -req -days 365 -in "$OUTPUT_DIR/server.csr" -CA "$OUTPUT_DIR/ca.crt" \
  -CAkey "$OUTPUT_DIR/ca.key" -CAcreateserial -out "$OUTPUT_DIR/server.crt" \
  -extfile "$OUTPUT_DIR/server.ext"

# Clean up temporary files
echo "7. Cleaning up temporary files..."
rm -f "$OUTPUT_DIR/server.csr" "$OUTPUT_DIR/server.ext" "$OUTPUT_DIR/ca.srl"

echo "Certificate generation complete!"
echo "Files created:"
echo "- CA Private Key: $OUTPUT_DIR/ca.key"
echo "- CA Certificate: $OUTPUT_DIR/ca.crt"
echo "- Server Private Key: $OUTPUT_DIR/server.key"
echo "- Server Certificate: $OUTPUT_DIR/server.crt"

echo "To use these certificates with your server:"
echo "- Use server.crt as your certificate file"
echo "- Use server.key as your private key file"
echo "- Clients should trust ca.crt to verify the server"