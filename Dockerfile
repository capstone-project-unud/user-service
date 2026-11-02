FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /service ./cmd/api

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
WORKDIR /app
COPY --from=build /service /app/service
USER 10001
ENV BIND_HOST=0.0.0.0 PORT=8082
EXPOSE 8082
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD wget -q -O /dev/null http://127.0.0.1:8082/health || exit 1
ENTRYPOINT ["/app/service"]
