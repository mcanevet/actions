FROM golang:1.26-alpine AS enrollsecureboot
RUN apk add --no-cache ca-certificates
COPY . /src
WORKDIR /src/enrollsecureboot
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o enrollsecureboot

FROM scratch
# Add Certificates into the image, for anything that does HTTPS calls
COPY --from=enrollsecureboot /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=enrollsecureboot /src/enrollsecureboot/enrollsecureboot /usr/bin/enrollsecureboot
ENTRYPOINT ["/usr/bin/enrollsecureboot"]
