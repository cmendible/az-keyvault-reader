#!/bin/bash
set -e
TLS_CERT_FILE="${TLS_CERT_FILE:-/var/lib/secrets/cert.crt}"
TLS_KEY_FILE="${TLS_KEY_FILE:-/var/lib/secrets/cert.key}"
LOG_LEVEL="${LOG_LEVEL:-2}"
echo "az-keyvault-reader-sidecar-injector starting at $(date) with TLS_CERT_FILE=${TLS_CERT_FILE} TLS_KEY_FILE=${TLS_KEY_FILE}"
set -x
exec az-keyvault-reader-sidecar-injector \
  --v="${LOG_LEVEL}" \
  --tls-cert-file="${TLS_CERT_FILE}" \
  --tls-key-file="${TLS_KEY_FILE}" \
  "$@"