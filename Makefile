.PHONY: help build up down restart logs clean test

help: ## Mostrar ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Construir imagen
	docker-compose build --no-cache

up: ## Levantar servidor
	docker-compose up -d

down: ## Detener servidor
	docker-compose down

restart: ## Reiniciar servidor
	docker-compose restart

logs: ## Ver logs en tiempo real
	docker-compose logs -f

status: ## Ver estado del servidor
	docker-compose ps

clean: ## Limpiar contenedores e imágenes
	docker-compose down --remove-orphans
	docker system prune -f

test: ## Probar endpoints
	@echo "Testing health endpoint..."
	curl -s http://localhost:3500/health | jq .
	@echo "\nTesting upload (requires API key)..."
	@echo "curl -X POST -H 'Authorization: Bearer \$$IMAGES_API_KEY' -F 'file=@test.txt' http://localhost:3500/upload"

shell: ## Acceder al contenedor
	docker-compose exec images-server sh

dev: ## Desarrollo local (Go)
	go run main.go

dev-build: ## Build y levantar
	docker-compose up --build -d

prod: ## Producción
	docker-compose up -d --build

backup: ## Backup del directorio de imágenes
	sudo tar -czf images_backup_$(shell date +%Y%m%d_%H%M%S).tar.gz /var/images

update: ## Actualizar desde Git y redesplegar
	git pull origin main
	docker-compose down
	docker-compose up --build -d

monitor: ## Monitorear recursos
	docker stats elastika-images