FROM golang:1.21-alpine as build

LABEL vendor="SecDim" \
    copyright="Security Dimension Pty Ltd. All rights reserved" \
    description="SecDim Sandbox Sarrif Parser" \
    version="1.0.0"

WORKDIR /app
ENV GOOS=linux

RUN apk add --no-cache git \
    && git clone --depth 1 https://github.com/secdim/sandbox-action.git

COPY . .
RUN go build -o sandbox .

FROM alpine:latest

WORKDIR /app

COPY --from=build /app/sandbox /app
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
