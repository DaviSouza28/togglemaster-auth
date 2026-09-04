# Etapa 1: compilação
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o auth-service .


# Etapa 2: imagem final
FROM alpine:3.20

WORKDIR /app

COPY --from=builder /app/auth-service .

EXPOSE 8001

CMD ["./auth-service"]
