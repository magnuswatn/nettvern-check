FROM golang:1.24-alpine3.21 AS builder

COPY main.go go.mod go.sum /src/
WORKDIR /src
RUN go install -trimpath

FROM alpine:3.21

COPY --from=builder /go/bin/nettvern-check /usr/local/bin/

ENTRYPOINT ["nettvern-check"]
