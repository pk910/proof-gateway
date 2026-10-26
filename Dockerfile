FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go page.html ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /proof-gateway .

FROM scratch
COPY --from=build /proof-gateway /proof-gateway
USER 65532:65532
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/proof-gateway", "-data", "/data"]
