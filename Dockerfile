# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o secure-urls main.go

FROM scratch
COPY --from=builder /app/secure-urls /secure-urls
EXPOSE 8080
ENTRYPOINT ["/secure-urls"] 