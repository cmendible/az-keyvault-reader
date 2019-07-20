FROM golang:1.12-alpine3.10 AS build
# Get CA certificates and install git
RUN apk update \
    && apk add ca-certificates \
    && rm -rf /var/cache/apk/* \
    && update-ca-certificates \
    && apk add git
# Create a dummy user
RUN echo "dummy:x:1001:1001:Dummy:/:" > /etc_passwd
WORKDIR /src
ADD go.mod go.sum ./
RUN go get -v
ADD az-keyvault-reader.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w'

FROM scratch
# Copy the CA certificates
COPY --from=build /etc/ssl/certs /etc/ssl/certs
EXPOSE 8333
COPY --from=build src/az-keyvault-reader /app/az-keyvault-reader
# Copy and use the dummy user 
COPY --from=build /etc_passwd /etc/passwd
USER dummy
CMD ["/app/az-keyvault-reader"]

# Metadata
ARG BUILD_DATE
ARG VCS_REF
LABEL org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.name="az-keyvault-reader" \
    org.label-schema.description="Exposes an endpoint to query Azure KeyVault Secrets with AAD Pod Identity" \
    org.label-schema.url="https://github.com/cmendible/az-keyvault-reader" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/cmendible/az-keyvault-reader" \
    org.label-schema.schema-version="0.1"