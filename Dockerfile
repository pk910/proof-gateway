# local build: docker build . -t pk910/proof-gateway:dev
FROM golang:1.27-alpine AS build
RUN apk add --no-cache git make
WORKDIR /src
COPY . .
RUN make build RELEASE=${RELEASE}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/bin/proof-gateway /proof-gateway
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/proof-gateway", "-data", "/data"]
