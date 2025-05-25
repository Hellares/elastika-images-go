package main

import (
	// "encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

func initLogger() {
	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var err error
	logger, err = config.Build()
	if err != nil {
		log.Fatal("Error al inicializar logger:", err)
	}
}

type ImageServer struct {
	ImagesDir   string
	APIKey      string
	PublicURL   string
	MaxFileSize int64
	Port        string
}

type UploadResponse struct {
	Path         string `json:"path"`
	URL          string `json:"url"`
	Size         int64  `json:"size"`
	MimeType     string `json:"mimetype"`
	Filename     string `json:"filename"`
	OriginalName string `json:"originalName"`
	TenantID     string `json:"tenantId"`
}

type FileInfo struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"createdAt"`
	ModifiedAt time.Time `json:"modifiedAt"`
	URL        string    `json:"url"`
}

type ListResponse struct {
	Success  bool       `json:"success"`
	Files    []FileInfo `json:"files"`
	Count    int        `json:"count"`
	TenantID string     `json:"tenantId"`
}

type QuotaResponse struct {
	TenantID      string         `json:"tenantId"`
	UsedBytes     int64          `json:"usedBytes"`
	UsedFormatted string         `json:"usedFormatted"`
	UsedMB        string         `json:"usedMB"`
	FileCount     int            `json:"fileCount"`
	FilesByType   map[string]int `json:"filesByType"`
	LastCheck     string         `json:"lastCheck"`
}

type HealthResponse struct {
	Status      string                 `json:"status"`
	Version     string                 `json:"version"`
	Uptime      int64                  `json:"uptime"`
	MemoryUsage map[string]interface{} `json:"memoryUsage"`
	Environment string                 `json:"environment"`
}

func NewImageServer() *ImageServer {
	// Cargar variables de entorno
	godotenv.Load()

	maxFileSize, _ := strconv.ParseInt(getEnv("MAX_FILE_SIZE", "20"), 10, 64)
	maxFileSize = maxFileSize * 1024 * 1024 // Convertir a bytes

	return &ImageServer{
		ImagesDir:   getEnv("IMAGES_DIR", "/var/www/images"),
		APIKey:      getEnv("API_KEY", "mathidev369"),
		PublicURL:   getEnv("PUBLIC_URL", "http://localhost:3500"),
		MaxFileSize: maxFileSize,
		Port:        getEnv("PORT", "3500"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (s *ImageServer) ensureImagesDir() error {
	if err := os.MkdirAll(s.ImagesDir, 0755); err != nil {
		return err
	}
	log.Printf("Usando directorio de imágenes: %s", s.ImagesDir)
	return nil
}

func (s *ImageServer) ensureTenantDir(tenantID string) (string, error) {
	// Validar tenantID para prevenir path traversal
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, tenantID)
	if !matched {
		return "", fmt.Errorf("ID de tenant inválido")
	}

	tenantDir := filepath.Join(s.ImagesDir, tenantID)
	if err := os.MkdirAll(tenantDir, 0755); err != nil {
		return "", err
	}
	return tenantDir, nil
}

func (s *ImageServer) sanitizeFilename(filename string) string {
	// Reemplazar caracteres no permitidos
	reg := regexp.MustCompile(`[^a-zA-Z0-9_.-]`)
	sanitized := reg.ReplaceAllString(filename, "_")

	// Limitar longitud
	if len(sanitized) > 200 {
		sanitized = sanitized[:200]
	}
	return sanitized
}

func (s *ImageServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Autenticación requerida"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != s.APIKey {
			c.JSON(http.StatusForbidden, gin.H{"error": "API key inválida"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (s *ImageServer) uploadHandler(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		logger.Error("Error al obtener archivo", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "No se proporcionó ningún archivo"})
		return
	}
	defer file.Close()

	// Verificar tamaño del archivo
	if header.Size > s.MaxFileSize {
		logger.Warn("Archivo demasiado grande",
			zap.Int64("size", header.Size),
			zap.Int64("maxSize", s.MaxFileSize))
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": fmt.Sprintf("Archivo demasiado grande. El límite es %dMB", s.MaxFileSize/(1024*1024)),
		})
		return
	}

	// Detectar tipo de archivo del contenido real
	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		logger.Error("Error al leer archivo para detectar tipo", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error al procesar archivo"})
		return
	}

	// Resetear el reader al inicio
	file.Seek(0, 0)

	mimeType := http.DetectContentType(buffer)

	// Si no se detecta correctamente, usar el header
	if mimeType == "application/octet-stream" {
		mimeType = header.Header.Get("Content-Type")
	}

	// Validar tipo de archivo
	if !s.isAllowedFileType(mimeType) {
		logger.Warn("Tipo de archivo no permitido",
			zap.String("mimeType", mimeType),
			zap.String("detectedType", http.DetectContentType(buffer)),
			zap.String("headerType", header.Header.Get("Content-Type")))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Tipo de archivo no permitido: %s", mimeType),
		})
		return
	}

	// Obtener y decodificar tenant ID
	tenantID := c.Query("path")
	if tenantID != "" {
		// Decodificar URL
		decoded, err := url.QueryUnescape(tenantID)
		if err != nil {
			logger.Warn("Error al decodificar path", zap.String("path", tenantID), zap.Error(err))
		} else {
			tenantID = decoded
		}

		parts := strings.Split(tenantID, "/")
		tenantID = parts[0]
	}
	if tenantID == "" {
		tenantID = c.GetHeader("x-tenant-id")
	}
	if tenantID == "" {
		tenantID = "default"
	}

	// Crear directorio del tenant
	tenantDir, err := s.ensureTenantDir(tenantID)
	if err != nil {
		logger.Error("Error al crear directorio del tenant",
			zap.String("tenantID", tenantID),
			zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID de tenant inválido"})
		return
	}

	// Generar nombre de archivo único
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)
	safeName := s.sanitizeFilename(header.Filename)
	filename := fmt.Sprintf("%d-%s", timestamp, safeName)
	filePath := filepath.Join(tenantDir, filename)

	logger.Info("Iniciando guardado de archivo",
		zap.String("tenantID", tenantID),
		zap.String("filename", filename),
		zap.String("originalName", header.Filename),
		zap.String("mimeType", mimeType),
		zap.Int64("size", header.Size))

	// Crear archivo directamente - SIN COMPRESIÓN
	dst, err := os.Create(filePath)
	if err != nil {
		logger.Error("Error al crear archivo",
			zap.String("path", filePath),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al crear archivo"})
		return
	}
	defer dst.Close()

	// Copiar contenido directamente desde el archivo original
	bytesWritten, err := io.Copy(dst, file)
	if err != nil {
		logger.Error("Error al guardar archivo",
			zap.String("path", filePath),
			zap.Error(err))
		// Limpiar archivo parcial en caso de error
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al guardar archivo"})
		return
	}

	// Establecer permisos
	os.Chmod(filePath, 0644)

	// Obtener información final del archivo
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		logger.Error("Error al obtener información del archivo",
			zap.String("path", filePath),
			zap.Error(err))
	}

	// Generar respuesta
	relativePath := filepath.Join(tenantID, filename)
	publicURL := fmt.Sprintf("%s/files/%s", s.PublicURL, relativePath)

	response := UploadResponse{
		Path:         relativePath,
		URL:          publicURL,
		Size:         fileInfo.Size(),
		MimeType:     mimeType,
		Filename:     filename,
		OriginalName: header.Filename,
		TenantID:     tenantID,
	}

	logger.Info("Archivo guardado exitosamente",
		zap.String("path", filePath),
		zap.Int64("bytesWritten", bytesWritten),
		zap.Int64("finalSize", fileInfo.Size()),
		zap.String("mimeType", mimeType),
		zap.String("publicURL", publicURL))

	c.JSON(http.StatusCreated, response)
}

func (s *ImageServer) isAllowedFileType(mimeType string) bool {
	allowed := map[string]struct{}{
		"image/jpeg":      {},
		"image/png":       {},
		"image/gif":       {},
		"image/webp":      {},
		"image/svg+xml":   {},
		"application/pdf": {},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": {},
		"application/msword": {},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {},
		"application/vnd.ms-excel": {},
		"text/csv":                 {},
	}

	_, exists := allowed[mimeType]
	return exists
}

func (s *ImageServer) deleteHandler(c *gin.Context) {
	// Usar filepath con wildcard
	relativePath := strings.TrimPrefix(c.Param("filepath"), "/")

	logger.Info("Request para eliminar archivo",
		zap.String("rawFilepath", c.Param("filepath")),
		zap.String("relativePath", relativePath))

	if relativePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ruta de archivo requerida"})
		return
	}

	// Decodificar URL si es necesario
	if decoded, err := url.QueryUnescape(relativePath); err == nil {
		relativePath = decoded
	}

	filePath := filepath.Join(s.ImagesDir, relativePath)

	logger.Info("Intentando eliminar archivo",
		zap.String("relativePath", relativePath),
		zap.String("fullPath", filePath))

	// Verificar que el archivo existe
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		logger.Warn("Archivo no encontrado para eliminar",
			zap.String("path", filePath))
		c.JSON(http.StatusNotFound, gin.H{"error": "Archivo no encontrado"})
		return
	}

	// Eliminar archivo
	if err := os.Remove(filePath); err != nil {
		logger.Error("Error al eliminar archivo",
			zap.String("path", filePath),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al eliminar archivo"})
		return
	}

	logger.Info("Archivo eliminado exitosamente", zap.String("path", filePath))
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"path":    relativePath,
	})
}

func (s *ImageServer) listHandler(c *gin.Context) {
	tenantID := c.Query("path")
	if tenantID == "" {
		tenantID = c.GetHeader("x-tenant-id")
	}
	if tenantID == "" {
		tenantID = "default"
	}

	tenantDir := filepath.Join(s.ImagesDir, tenantID)

	// Verificar si el directorio existe
	if _, err := os.Stat(tenantDir); os.IsNotExist(err) {
		c.JSON(http.StatusOK, ListResponse{
			Success:  true,
			Files:    []FileInfo{},
			Count:    0,
			TenantID: tenantID,
		})
		return
	}

	// Leer archivos
	entries, err := os.ReadDir(tenantDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al leer directorio"})
		return
	}

	var files []FileInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			relativePath := filepath.Join(tenantID, entry.Name())
			publicURL := fmt.Sprintf("%s/files/%s", s.PublicURL, relativePath)

			files = append(files, FileInfo{
				Name:       entry.Name(),
				Path:       relativePath,
				Size:       info.Size(),
				CreatedAt:  info.ModTime(),
				ModifiedAt: info.ModTime(),
				URL:        publicURL,
			})
		}
	}

	c.JSON(http.StatusOK, ListResponse{
		Success:  true,
		Files:    files,
		Count:    len(files),
		TenantID: tenantID,
	})
}

func (s *ImageServer) serveFileHandler(c *gin.Context) {
	// Con wildcard /*filepath, usar "filepath" en lugar de "path"
	// Wildcard incluye la barra inicial, así que la quitamos
	relativePath := strings.TrimPrefix(c.Param("filepath"), "/")

	// Log para debugging
	logger.Info("Request para servir archivo",
		zap.String("rawFilepath", c.Param("filepath")),
		zap.String("relativePath", relativePath),
		zap.String("requestURL", c.Request.URL.String()))

	// Verificar que no esté vacío
	if relativePath == "" {
		logger.Warn("Path vacío en request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ruta de archivo requerida"})
		return
	}

	// Decodificar URL si es necesario
	if decoded, err := url.QueryUnescape(relativePath); err == nil {
		if decoded != relativePath {
			logger.Info("Path decodificado",
				zap.String("original", relativePath),
				zap.String("decoded", decoded))
			relativePath = decoded
		}
	}

	// Construir path completo
	filePath := filepath.Join(s.ImagesDir, relativePath)

	logger.Info("Intentando servir archivo",
		zap.String("relativePath", relativePath),
		zap.String("fullPath", filePath))

	// Verificar que el archivo existe
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		logger.Warn("Archivo no encontrado",
			zap.String("path", filePath))

		// Debugging: listar archivos del directorio
		dir := filepath.Dir(filePath)
		if entries, err := os.ReadDir(dir); err == nil {
			var files []string
			for _, entry := range entries {
				if !entry.IsDir() {
					files = append(files, entry.Name())
				}
			}
			logger.Info("Archivos disponibles en directorio",
				zap.String("directory", dir),
				zap.Strings("files", files))
		}

		c.JSON(http.StatusNotFound, gin.H{
			"error": "Archivo no encontrado",
			"path":  relativePath,
		})
		return
	}

	if err != nil {
		logger.Error("Error al acceder archivo",
			zap.String("path", filePath),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al acceder archivo"})
		return
	}

	// Verificar que no es un directorio
	if fileInfo.IsDir() {
		logger.Warn("Ruta es un directorio",
			zap.String("path", filePath))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ruta especificada es un directorio"})
		return
	}

	// Detectar tipo de contenido
	ext := strings.ToLower(filepath.Ext(filePath))
	contentType := "application/octet-stream"

	switch ext {
	case ".jpg", ".jpeg":
		contentType = "image/jpeg"
	case ".png":
		contentType = "image/png"
	case ".gif":
		contentType = "image/gif"
	case ".webp":
		contentType = "image/webp"
	case ".pdf":
		contentType = "application/pdf"
	}

	// Configurar headers
	c.Header("Content-Type", contentType)
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	c.Header("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	logger.Info("Sirviendo archivo exitosamente",
		zap.String("path", filePath),
		zap.String("contentType", contentType),
		zap.Int64("size", fileInfo.Size()))

	// Servir archivo
	c.File(filePath)
}

func (s *ImageServer) quotaHandler(c *gin.Context) {
	tenantID := c.Param("tenantId")

	// Validar tenantID
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, tenantID)
	if !matched {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID de tenant inválido"})
		return
	}

	tenantDir := filepath.Join(s.ImagesDir, tenantID)

	var totalSize int64
	var fileCount int
	filesByType := make(map[string]int)

	// Caminar por el directorio recursivamente
	filepath.Walk(tenantDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() {
			totalSize += info.Size()
			fileCount++

			ext := strings.ToLower(filepath.Ext(info.Name()))
			filesByType[ext]++
		}
		return nil
	})

	// Formatear tamaño
	usedFormatted := formatSize(totalSize)
	usedMB := fmt.Sprintf("%.2f", float64(totalSize)/(1024*1024))

	response := QuotaResponse{
		TenantID:      tenantID,
		UsedBytes:     totalSize,
		UsedFormatted: usedFormatted,
		UsedMB:        usedMB,
		FileCount:     fileCount,
		FilesByType:   filesByType,
		LastCheck:     time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.2f KB", float64(bytes)/1024)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GB", float64(bytes)/(1024*1024*1024))
}

func (s *ImageServer) healthHandler(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Verificar que el directorio de imágenes sea accesible
	_, err := os.Stat(s.ImagesDir)
	isHealthy := err == nil

	status := "ok"
	httpStatus := http.StatusOK
	if !isHealthy {
		status = "error"
		httpStatus = http.StatusServiceUnavailable
	}

	response := HealthResponse{
		Status:  status,
		Version: getEnv("VERSION", "1.0.0"),
		Uptime:  time.Now().Unix() - startTime,
		MemoryUsage: map[string]interface{}{
			"alloc":      formatSize(int64(m.Alloc)),
			"totalAlloc": formatSize(int64(m.TotalAlloc)),
			"sys":        formatSize(int64(m.Sys)),
			"numGC":      m.NumGC,
		},
		Environment: getEnv("NODE_ENV", "development"),
	}

	// Para HEAD requests, solo devolver headers
	if c.Request.Method == "HEAD" {
		c.Status(httpStatus)
		return
	}

	c.JSON(httpStatus, response)
}

var startTime int64

func main() {
	startTime = time.Now().Unix()

	// Inicializar logger
	initLogger()
	defer logger.Sync()

	server := NewImageServer()

	// Crear directorio de imágenes
	if err := server.ensureImagesDir(); err != nil {
		logger.Fatal("Error al crear directorio de imágenes", zap.Error(err))
	}

	// Configurar Gin
	env := getEnv("NODE_ENV", "development")
	if env == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.Default()

	// Configuración de seguridad
	r.Use(gin.Recovery())
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: []string{"/health"},
	}))

	// Configurar proxies de confianza
	if env == "production" {
		trustedProxies := strings.Split(getEnv("TRUSTED_PROXIES", "127.0.0.1"), ",")
		r.SetTrustedProxies(trustedProxies)
		logger.Info("Proxies de confianza configurados",
			zap.Strings("proxies", trustedProxies))
	} else {
		r.SetTrustedProxies(nil)
		logger.Info("Modo desarrollo: confiando en todos los proxies")
	}

	// CORS
	corsConfig := cors.Config{
		AllowMethods:     []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Tenant-ID"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	if env == "production" {
		corsConfig.AllowOrigins = strings.Split(getEnv("ALLOWED_ORIGINS", "http://localhost:3000"), ",")
	} else {
		corsConfig.AllowAllOrigins = true
	}

	r.Use(cors.New(corsConfig))

	// ========================================
	// RUTAS PÚBLICAS
	// ========================================
	
	r.GET("/health", server.healthHandler)
	r.HEAD("/health", server.healthHandler)
	
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "Elastika Images Server",
			"status":  "running",
			"version": getEnv("VERSION", "1.0.0"),
		})
	})

	// ========================================
	// RUTAS DE ARCHIVOS - SIN GRUPO (ALTERNATIVA)
	// ========================================
	
	// Ruta específica PRIMERO
	r.GET("/files-list", server.listHandler)  // Cambiar URL para evitar conflicto
	
	// Handler personalizado para archivos
	r.GET("/files/*filepath", server.serveFileHandler)

	// ========================================
	// RUTAS PROTEGIDAS
	// ========================================
	
	protected := r.Group("/")
	protected.Use(server.authMiddleware())
	{
		protected.POST("/upload", server.uploadHandler)
		protected.DELETE("/files/*filepath", server.deleteHandler)  // Directo sin grupo
		protected.GET("/quota/:tenantId", server.quotaHandler)
	}

	logger.Info("Servidor iniciado exitosamente",
		zap.String("port", server.Port),
		zap.String("imagesDir", server.ImagesDir),
		zap.String("environment", env),
		zap.String("publicURL", server.PublicURL))

	r.Run(":" + server.Port)
}