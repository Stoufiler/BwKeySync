# Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o bwkeysync .

# Runtime stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/bwkeysync .

# Set up timezone
RUN apk --no-cache add tzdata

# Create non-root user
RUN adduser -D -g '' appuser
USER appuser

ENTRYPOINT ["./bwkeysync"]
