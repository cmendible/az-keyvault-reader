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
ADD main.go ./
ADD webhook.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w'

FROM alpine:latest
ENV TLS_CERT_FILE=/var/lib/secrets/cert.crt \
    TLS_KEY_FILE=/var/lib/secrets/cert.key
RUN apk --no-cache add bash
# Copy the CA certificates
COPY --from=build /etc/ssl/certs /etc/ssl/certs
EXPOSE 8443
# Copy and use the dummy user 
COPY --from=build /etc_passwd /etc/passwd
COPY --from=build src/az-keyvault-reader-sidecar-injector /bin/az-keyvault-reader-sidecar-injector
COPY ./entrypoint.sh /bin/entrypoint.sh
USER dummy
ENTRYPOINT ["entrypoint.sh"]
CMD []