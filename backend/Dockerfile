FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/andromeda ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/andromeda /app/andromeda
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/andromeda"]
