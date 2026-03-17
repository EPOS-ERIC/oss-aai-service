FROM golang:1.26.1-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/oss-aaai .

FROM alpine:3.22

WORKDIR /app

RUN adduser -D -g '' appuser

COPY --from=builder /out/oss-aaai /app/oss-aaai
COPY --from=builder /app/templates /app/templates

RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

CMD ["/app/oss-aaai"]
