./create_key_pair.sh \
    --service az-keyvault-reader-injector-service \
    --secret az-keyvault-reader-injector \
    --namespace kube-system
    
./patch_ca_bundle.sh
