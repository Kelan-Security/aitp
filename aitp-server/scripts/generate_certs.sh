#!/bin/bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/C=US/ST=Dev/L=Dev/O=Kernex/OU=AITP/CN=localhost"
echo "Certificates generated in certs/"
