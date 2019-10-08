docker build -t cmendibl3/az-keyvault-reader-sidecar-injector:latest .

# openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./cert.key -out ./cert.crt -subj "/CN=localhost"
# kubectl create secret generic az-keyvault-reader-sidecar-injector --from-file=./cert.crt --from-file=./cert.key --namespace=kube-system
# CABUNDLE_BASE64="$(cat $DEPLOYMENT/$CLUSTER/ca.crt |base64|tr -d '\n')"
# sed -i '' -e "s|__CA_BUNDLE_BASE64__|$CABUNDLE_BASE64|g" ./k8s/mutating-webhook-configuration.yaml