#!/usr/bin/env bash
# Usage: ./scripts/deploy.sh yourdomain.com your@email.com
set -e
DOMAIN=$1
EMAIL=$2

[ -z "$DOMAIN" ] && { echo "Usage: $0 <domain> <email>"; exit 1; }

# Generate .env.prod if not exists
[ -f .env.prod ] || cat > .env.prod << EOF
POSTGRES_PASSWORD=$(openssl rand -base64 32)
AITP_JWT_SECRET=$(openssl rand -base64 64)
GEMINI_API_KEY=[REDACTED_GEMINI_KEY]
EOF
echo "Created .env.prod — add your GEMINI_API_KEY"

# Get TLS cert
docker compose -f docker-compose.prod.yml run --rm certbot certonly \
  --webroot --webroot-path=/var/www/certbot \
  --email "$EMAIL" --agree-tos --no-eff-email \
  -d "$DOMAIN"

# Start full stack
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d

echo "✓ Kernex deployed at https://$DOMAIN"
