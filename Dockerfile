# Etapa de construcción
FROM golang:1.21-alpine AS builder

# Instalar dependencias de sistema
RUN apk add --no-cache git ca-certificates tzdata

# Configurar directorio de trabajo
WORKDIR /app

# Copiar go mod files para cachear dependencias
COPY go.mod go.sum ./

# Descargar dependencias
RUN go mod download

# Copiar código fuente
COPY . .

# Compilar la aplicación
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o main .

# Etapa de producción
FROM alpine:latest

# Instalar dependencias básicas
RUN apk --no-cache add ca-certificates tzdata wget

# Crear usuario no-root
RUN addgroup -g 1001 -S elastika && \
    adduser -S elastika -u 1001 -G elastika

# Configurar directorio de trabajo
WORKDIR /app

# Crear directorios necesarios
RUN mkdir -p /var/www/images logs && \
    chown -R elastika:elastika /var/www/images logs /app && \
    chmod -R 755 /var/www/images

# Copiar el binario desde la etapa de build
COPY --from=builder /app/main .
COPY --chown=elastika:elastika .env* ./

# Cambiar a usuario no-root
USER elastika

# Exponer puerto
EXPOSE 3500

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3500/health || exit 1

# Comando para ejecutar
CMD ["./main"]