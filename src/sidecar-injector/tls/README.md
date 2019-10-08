openssl genrsa -out rootCA.key 4096
openssl req -x509 -config ca.config -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.crt
openssl genrsa -out cert.key 2048
openssl req -new -key cert.key -out cert.csr -config csr.config
openssl x509 -req -in cert.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out cert.crt -days 1024 -sha256 -extensions req_ext -extfile csr.config
CABUNDLE_BASE64="$(cat rootCA.crt | base64 | tr -d '\n')"
sed -i'' -e "s|__CA_BUNDLE_BASE64__|$CABUNDLE_BASE64|g" ../k8s/mutating-webhook-configuration.yaml

kubectl create secret generic az-keyvault-reader-sidecar-injector --from-file=./cert.crt --from-file=./cert.key --namespace=kube-system
