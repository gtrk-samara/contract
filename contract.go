package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"

	"golang.org/x/crypto/bcrypt"
)

// Секретный ключ для JWT
var jwtSecret = []byte("your-secure-random-secret-key")

// Пользователь для аутентификации
type User struct {
	ID           int    `json:"id"`
	Login        string `json:"login"`
	Password     string `json:"password,omitempty"` // Пароль из JSON (для создания пользователя)
	PasswordHash string `json:"-"`                  // Хэш пароля из базы данных (не отправляется в JSON)
	Role         string `json:"role"`
	Surname      string `json:"surname"`
	Name         string `json:"name"`
	Patronymic   string `json:"patronymic"`
}

// Токен аутентификации
//type AuthResponse struct {
//	Token string `json:"token"`
//}

// Структура контракта (без изменений)
type Contract struct {
	ID                            int     `json:"id"`
	Date                          string  `json:"date"`
	Number                        string  `json:"number"`
	Name                          string  `json:"name"`
	Supplier                      string  `json:"supplier"`
	Status                        string  `json:"status"`
	FilePath                      *string `json:"file_path"`
	AddAgreementPath              *string `json:"add_agreement_path"`
	DisagreementProtocolPath      *string `json:"disagreement_protocol_path"`
	LawyerEditedFilePath          *string `json:"lawyer_edited_file_path"`
	ChiefAccountantEditedFilePath *string `json:"chief_accountant_edited_file_path"`
	History                       string  `json:"history"`
	Movement                      string  `json:"movement"`
	LawyerStatus                  *string `json:"lawyer_status"`
	ChiefAccountantStatus         *string `json:"chief_accountant_status"`
	CounterpartyStatus            *string `json:"counterparty_status"`
	Curator                       string  `json:"curator"`
	SignedFilePath                *string `json:"signed_file_path"`
	IsSignedElectronically        bool    `json:"is_signed_electronically"`
}

// Структура контрагента (без изменений)
type Counterparty struct {
	ID              int     `json:"id"`
	Name            string  `json:"name"`
	INN             *string `json:"inn,omitempty"`
	KPP             *string `json:"kpp,omitempty"`
	OGRN            *string `json:"ogrn,omitempty"`
	BIK             *string `json:"bik,omitempty"`
	BankName        *string `json:"bank_name,omitempty"`
	AccountNumber   *string `json:"account_number,omitempty"`
	DirectorName    *string `json:"director_name,omitempty"`
	DirectorPhone   *string `json:"director_phone,omitempty"`
	ManagerName     *string `json:"manager_name,omitempty"`
	ManagerPhone    *string `json:"manager_phone,omitempty"`
	LegalAddress    *string `json:"legal_address,omitempty"`
	PhysicalAddress *string `json:"physical_address,omitempty"`
	Comment         *string `json:"comment,omitempty"`
}

const (
	lawyerFilePrefix          = "ЮРИСТ"
	chiefAccountantFilePrefix = "ГЛАВБУХ"
)

// encodeRFC5987 кодирует имя файла для использования в Content-Disposition согласно RFC 5987
func encodeRFC5987(filename string) string {
	var encoded strings.Builder
	for _, r := range filename {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '~' {
			encoded.WriteRune(r)
		} else {
			bytes := []byte(string(r))
			for _, b := range bytes {
				encoded.WriteString(fmt.Sprintf("%%%02X", b))
			}
		}
	}
	return encoded.String()
}

// generateFileName генерирует имя файла с суффиксами ЮРИСТ и ГЛАВБУХ
func generateFileName(baseName, suffix, timestamp, extension string) string {
	return baseName + "_" + suffix + "_" + timestamp + extension
}

// sanitizeFolderName очищает имя папки от недопустимых символов
func sanitizeFolderName(name string) string {
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*]`)
	sanitized := invalidChars.ReplaceAllString(name, "")
	sanitized = strings.TrimSpace(sanitized)
	sanitized = regexp.MustCompile(`\s+`).ReplaceAllString(sanitized, "_")
	if sanitized == "" {
		return "UnknownSupplier"
	}
	return sanitized
}

// Проверка JWT и роли
func authMiddleware(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Требуется токен авторизации"})
			c.Abort()
			return
		}

		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный формат токена"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("неожиданный метод подписи: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный или истекший токен"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные данные токена"})
			c.Abort()
			return
		}

		role := claims["role"].(string)
		allowed := false
		for _, allowedRole := range allowedRoles {
			if role == allowedRole {
				allowed = true
				break
			}
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Недостаточно прав доступа"})
			c.Abort()
			return
		}

		userID, _ := claims["user_id"].(float64)
		c.Set("user_id", int(userID))
		c.Set("role", role)
		c.Next()
	}
}

func validateToken(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен отсутствует"})
		return
	}
	token := strings.TrimPrefix(tokenString, "Bearer ")
	// Здесь должна быть логика проверки токена (например, с использованием JWT)
	// Для простоты предполагаем, что токен валиден, если он не пустой
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Токен валиден"})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Ошибка загрузки .env файла: ", err)
	}

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		log.Fatal("JWT_SECRET не установлен в переменных окружения")
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.MaxMultipartMemory = 10 << 20 // 10 MB

	// Логгирование подключений
	r.Use(func(c *gin.Context) {
		startTime := time.Now()
		clientIP := c.ClientIP()
		method := c.Request.Method
		path := c.Request.URL.Path
		fmt.Printf("[🔌] %s - %s %s подключение от %s\n", startTime.Format("2006-01-02 15:04:05"), method, path, clientIP)
		c.Next()
		statusCode := c.Writer.Status()
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		fmt.Printf("[✅] %s - %s %s [%d] от %s (время: %v)\n", endTime.Format("2006-01-02 15:04:05"), method, path, statusCode, clientIP, duration)
	})

	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	db, err := sql.Open("sqlite3", "./contracts.db")
	if err != nil {
		log.Fatal("Ошибка подключения к базе данных: ", err)
	}
	defer db.Close()

	// Включение поддержки внешних ключей
	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		log.Fatal("Ошибка включения внешних ключей: ", err)
	}

	// Создание таблиц
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS contracts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			date TEXT,
			number TEXT,
			name TEXT NOT NULL,
			supplier TEXT NOT NULL,
			status TEXT NOT NULL,
			file_path TEXT,
			add_agreement_path TEXT,
			disagreement_protocol_path TEXT,
			lawyer_edited_file_path TEXT,
			chief_accountant_edited_file_path TEXT,
			history TEXT,
			movement TEXT,
			lawyer_status TEXT,
			chief_accountant_status TEXT,
			counterparty_status TEXT,
			curator TEXT NOT NULL,
			signed_file_path TEXT,
			is_signed_electronically BOOLEAN DEFAULT FALSE
		)
	`)
	if err != nil {
		panic("Ошибка создания таблицы contracts: " + err.Error())
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS counterparties (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			inn TEXT,
			kpp TEXT,
			ogrn TEXT,
			bik TEXT,
			bank_name TEXT,
			account_number TEXT,
			director_name TEXT,
			director_phone TEXT,
			manager_name TEXT,
			manager_phone TEXT,
			legal_address TEXT,
			physical_address TEXT,
			comment TEXT
		)
	`)
	if err != nil {
		panic("Ошибка создания таблицы counterparties: " + err.Error())
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS curators (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			surname TEXT NOT NULL,
			name TEXT NOT NULL,
			patronymic TEXT NOT NULL,
			user_id INTEGER,
			UNIQUE(surname, name, patronymic),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		panic("Ошибка создания таблицы curators: " + err.Error())
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			login TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL CHECK(role IN ('curator', 'lawyer', 'chief_accountant', 'chief_engineer', 'admin')),
			surname TEXT NOT NULL,
			name TEXT NOT NULL,
			patronymic TEXT NOT NULL
		)
	`)
	if err != nil {
		panic("Ошибка создания таблицы users: " + err.Error())
	}

	// создание индексов после создания таблиц
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_contracts_curator ON contracts(curator);`)
	if err != nil {
		log.Fatal("Ошибка создания индекса idx_contracts_curator: ", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_users_login ON users(login);`)
	if err != nil {
		log.Fatal("Ошибка создания индекса idx_users_login: ", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_counterparties_name ON counterparties(name);`)
	if err != nil {
		log.Fatal("Ошибка создания индекса idx_counterparties_name: ", err)
	}

	// Маршрут для проверки токена
	r.GET("/validate-token", validateToken)

	// Маршрут для входа
	r.POST("/login", func(c *gin.Context) {
		log.Println("\n\n=== DEBUG LOGIN HANDLER ===")
		log.Printf("Request Body: %v", c.Request.Body)

		// Структура для получения данных входа
		var credentials struct {
			Login    string `json:"login" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		// Получаем и валидируем данные
		if err := c.ShouldBindJSON(&credentials); err != nil {
			log.Printf("[AUTH] Invalid request format: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Неверный формат данных",
				"details": err.Error(),
			})
			return
		}

		// Логирование попытки входа (без пароля в логах!)
		log.Printf("[AUTH] Login attempt for user: %s", credentials.Login)

		// Ищем пользователя в базе
		var user User
		err := db.QueryRow(`
			SELECT id, login, password_hash, role, surname, name, patronymic 
			FROM users 
			WHERE login = ?`,
			strings.TrimSpace(credentials.Login)).
			Scan(
				&user.ID,
				&user.Login,
				&user.PasswordHash, // Используем PasswordHash для хэша из базы
				&user.Role,
				&user.Surname,
				&user.Name,
				&user.Patronymic,
			)

		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("[AUTH] User not found: %s", credentials.Login)
				// Задержка для защиты от брутфорса
				time.Sleep(1 * time.Second)
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "Неверный логин или пароль",
					"details": "user not found",
				})
				return
			}

			log.Printf("[AUTH] Database error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Ошибка сервера",
				"details": err.Error(),
			})
			return
		}

		// Сравниваем пароль с хешем
		err = bcrypt.CompareHashAndPassword(
			[]byte(user.PasswordHash),
			[]byte(credentials.Password),
		)
		if err != nil {
			log.Printf("[AUTH] Invalid password for user: %s", user.Login)
			// Задержка для защиты от брутфорса
			time.Sleep(1 * time.Second)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Неверный логин или пароль",
				"details": "password mismatch",
			})
			return
		}

		// Создаем JWT токен
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": user.ID,
			"role":    user.Role,
			"exp":     time.Now().Add(time.Hour * 24).Unix(), // 24 часа
			"login":   user.Login,
		})

		// Подписываем токен
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			log.Printf("[AUTH] Token generation error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Ошибка генерации токена",
				"details": err.Error(),
			})
			return
		}

		// Формируем полное имя пользователя
		fullName := fmt.Sprintf("%s %s %s",
			user.Surname,
			user.Name,
			user.Patronymic)

		log.Printf("[AUTH] Successful login for: %s (%s)", user.Login, fullName)

		// Возвращаем успешный ответ
		c.JSON(http.StatusOK, gin.H{
			"token": tokenString,
			"role":  user.Role,
			"user": gin.H{
				"id":         user.ID,
				"login":      user.Login,
				"surname":    user.Surname,
				"name":       user.Name,
				"patronymic": user.Patronymic,
				"fullName":   fmt.Sprintf("%s %s %s", user.Surname, user.Name, user.Patronymic),
			},
		})
	})

	// Маршрут для регистрации пользователей (доступен только админу)
	r.POST("/users", authMiddleware("admin"), func(c *gin.Context) {
		var newUser User
		if err := c.BindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
			return
		}

		if newUser.Login == "" || newUser.Password == "" || newUser.Role == "" || newUser.Surname == "" || newUser.Name == "" || newUser.Patronymic == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Все поля обязательны"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка хэширования пароля"})
			return
		}

		result, err := db.Exec(
			"INSERT INTO users (login, password_hash, role, surname, name, patronymic) VALUES (?, ?, ?, ?, ?, ?)",
			newUser.Login, string(hashedPassword), newUser.Role, newUser.Surname, newUser.Name, newUser.Patronymic,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка добавления пользователя: " + err.Error()})
			return
		}

		id, _ := result.LastInsertId()
		newUser.ID = int(id)

		if newUser.Role == "curator" {
			_, err = db.Exec(
				"INSERT INTO curators (surname, name, patronymic, user_id) VALUES (?, ?, ?, ?)",
				newUser.Surname, newUser.Name, newUser.Patronymic, newUser.ID,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка добавления куратора: " + err.Error()})
				return
			}
		}

		c.JSON(http.StatusOK, newUser)
	})

	// Защищенные маршруты для договоров
	r.POST("/contracts", authMiddleware("curator", "admin", "chief_engineer"), func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		role, _ := c.Get("role")

		var contract Contract
		contract.Date = c.PostForm("date")
		contract.Number = c.PostForm("number")
		contract.Name = c.PostForm("name")
		contract.Supplier = c.PostForm("supplier")
		contract.Movement = c.PostForm("movement")
		contract.Status = "Получение шаблона"
		contract.LawyerStatus = new(string)
		*contract.LawyerStatus = "Ожидает проверки"
		contract.ChiefAccountantStatus = new(string)
		*contract.ChiefAccountantStatus = "Ожидает проверки"
		contract.CounterpartyStatus = new(string)
		*contract.CounterpartyStatus = "Ожидает шаблон"
		contract.History = time.Now().Format("02.01.2006 15:04") + " - Договор создан"
		contract.Curator = c.PostForm("curator")

		if contract.Curator == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Куратор обязателен для указания"})
			return
		}

		if role == "curator" {
			var userCurator string
			err := db.QueryRow(
				"SELECT surname || ' ' || name || ' ' || patronymic FROM users WHERE id = ?",
				userID,
			).Scan(&userCurator)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки куратора: " + err.Error()})
				return
			}
			if contract.Curator != userCurator {
				c.JSON(http.StatusForbidden, gin.H{"error": "Куратор может создавать договоры только с собой в качестве куратора"})
				return
			}
		}

		var existingID int
		err := db.QueryRow("SELECT id FROM counterparties WHERE name = ?", contract.Supplier).Scan(&existingID)
		if err == sql.ErrNoRows {
			_, err = db.Exec("INSERT INTO counterparties (name) VALUES (?)", contract.Supplier)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка добавления контрагента: " + err.Error()})
				return
			}
		}

		uploadFolder := "D:\\contract\\uploads"
		supplierFolderName := sanitizeFolderName(contract.Supplier)
		supplierFolderPath := filepath.Join(uploadFolder, supplierFolderName)
		if err := os.MkdirAll(supplierFolderPath, os.ModePerm); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания папки: " + err.Error()})
			return
		}

		timestamp := time.Now().Format("20060102150405")
		var filePath *string
		file, err := c.FormFile("file")
		if err == nil && file != nil {
			extension := filepath.Ext(file.Filename)
			baseName := filepath.Base(file.Filename[:len(file.Filename)-len(extension)])
			uniqueFileName := baseName + "_" + timestamp + extension
			absolutePath := filepath.Join(supplierFolderPath, uniqueFileName)
			if err := c.SaveUploadedFile(file, absolutePath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки файла договора: " + err.Error()})
				return
			}
			filePath = &absolutePath
		}

		result, err := db.Exec(
			"INSERT INTO contracts (date, number, name, supplier, status, file_path, history, movement, lawyer_status, chief_accountant_status, counterparty_status, curator) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			contract.Date, contract.Number, contract.Name, contract.Supplier, contract.Status, filePath, contract.History, contract.Movement, contract.LawyerStatus, contract.ChiefAccountantStatus, contract.CounterpartyStatus, contract.Curator,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка добавления договора: " + err.Error()})
			return
		}
		id, _ := result.LastInsertId()
		contract.ID = int(id)
		c.JSON(http.StatusOK, contract)
	})

	r.PUT("/contracts/:id", authMiddleware("curator", "lawyer", "chief_accountant", "chief_engineer", "admin"), func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}

		userID, _ := c.Get("user_id")
		role, _ := c.Get("role")

		var current Contract
		err = db.QueryRow(
			"SELECT date, number, name, supplier, status, file_path, add_agreement_path, disagreement_protocol_path, lawyer_edited_file_path, chief_accountant_edited_file_path, history, movement, lawyer_status, chief_accountant_status, counterparty_status, curator, signed_file_path, is_signed_electronically FROM contracts WHERE id = ?",
			id,
		).Scan(&current.Date, &current.Number, &current.Name, &current.Supplier, &current.Status, &current.FilePath, &current.AddAgreementPath, &current.DisagreementProtocolPath, &current.LawyerEditedFilePath, &current.ChiefAccountantEditedFilePath, &current.History, &current.Movement, &current.LawyerStatus, &current.ChiefAccountantStatus, &current.CounterpartyStatus, &current.Curator, &current.SignedFilePath, &current.IsSignedElectronically)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Договор не найден: " + err.Error()})
			return
		}

		if role == "curator" {
			var userCurator string
			err := db.QueryRow(
				"SELECT surname || ' ' || name || ' ' || patronymic FROM users WHERE id = ?",
				userID,
			).Scan(&userCurator)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки куратора: " + err.Error()})
				return
			}
			if current.Curator != userCurator {
				c.JSON(http.StatusForbidden, gin.H{"error": "Куратор может редактировать только свои договоры"})
				return
			}
		}

		var filePath, addAgreementPath, disagreementProtocolPath, lawyerEditedFilePath, chiefAccountantEditedFilePath, signedFilePath *string
		timestamp := time.Now().Format("20060102150405")

		date := c.Request.FormValue("date")
		number := c.Request.FormValue("number")
		name := c.Request.FormValue("name")
		supplier := c.Request.FormValue("supplier")
		status := c.Request.FormValue("status")
		movement := c.Request.FormValue("movement")
		uploadFolder := c.Request.FormValue("uploadFolder")
		lawyerStatus := c.Request.FormValue("lawyer_status")
		chiefAccountantStatus := c.Request.FormValue("chief_accountant_status")
		counterpartyStatus := c.Request.FormValue("counterparty_status")
		curator := c.Request.FormValue("curator")
		signedFile, _ := c.FormFile("signed_file")
		isSignedElectronically := c.Request.FormValue("is_signed_electronically") == "true"

		if role == "curator" && curator != current.Curator {
			c.JSON(http.StatusForbidden, gin.H{"error": "Куратор не может изменить назначенного куратора"})
			return
		}

		if role == "lawyer" {
			if lawyerStatus == "" || lawyerStatus == *current.LawyerStatus {
				lawyerStatus = *current.LawyerStatus
			} else if lawyerStatus != "Ожидает проверки" && lawyerStatus != "Проверяет" && lawyerStatus != "Согласовал" && lawyerStatus != "Внес правки" && lawyerStatus != "Протокол разногласий" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Недопустимый статус юриста"})
				return
			}
			date = current.Date
			number = current.Number
			name = current.Name
			supplier = current.Supplier
			status = current.Status
			movement = current.Movement
			chiefAccountantStatus = *current.ChiefAccountantStatus
			counterpartyStatus = *current.CounterpartyStatus
			curator = current.Curator
			isSignedElectronically = current.IsSignedElectronically
		}

		if role == "chief_accountant" {
			if chiefAccountantStatus == "" || chiefAccountantStatus == *current.ChiefAccountantStatus {
				chiefAccountantStatus = *current.ChiefAccountantStatus
			} else if chiefAccountantStatus != "Ожидает проверки" && chiefAccountantStatus != "Проверяет" && chiefAccountantStatus != "Согласовал" && chiefAccountantStatus != "Внес правки" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Недопустимый статус главбуха"})
				return
			}
			date = current.Date
			number = current.Number
			name = current.Name
			supplier = current.Supplier
			status = current.Status
			movement = current.Movement
			lawyerStatus = *current.LawyerStatus
			counterpartyStatus = *current.CounterpartyStatus
			curator = current.Curator
			isSignedElectronically = current.IsSignedElectronically
		}

		if role == "chief_engineer" {
			date = current.Date
			number = current.Number
			name = current.Name
			supplier = current.Supplier
			status = current.Status
			lawyerStatus = *current.LawyerStatus
			chiefAccountantStatus = *current.ChiefAccountantStatus
			counterpartyStatus = *current.CounterpartyStatus
			curator = current.Curator
			isSignedElectronically = current.IsSignedElectronically
		}

		supplierFolderName := sanitizeFolderName(supplier)
		supplierFolderPath := filepath.Join(uploadFolder, supplierFolderName)
		if uploadFolder == "" {
			uploadFolder = "D:\\contract\\Uploads"
		}

		if err := os.MkdirAll(supplierFolderPath, os.ModePerm); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания папки: " + err.Error()})
			return
		}

		file, _ := c.FormFile("file")
		addAgreement, _ := c.FormFile("add_agreement")
		disagreementProtocol, _ := c.FormFile("disagreement_protocol")
		lawyerEditedFile, _ := c.FormFile("lawyer_edited_file")
		chiefAccountantEditedFile, _ := c.FormFile("chief_accountant_edited_file")

		if file != nil && (role == "curator" || role == "admin") {
			extension := filepath.Ext(file.Filename)
			baseName := filepath.Base(file.Filename[:len(file.Filename)-len(extension)])
			uniqueFileName := baseName + "_" + timestamp + extension
			absolutePath := filepath.Join(supplierFolderPath, uniqueFileName)
			if err := c.SaveUploadedFile(file, absolutePath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки файла договора: " + err.Error()})
				return
			}
			filePath = &absolutePath
		}

		if addAgreement != nil && (role == "curator" || role == "chief_engineer" || role == "admin") {
			extension := filepath.Ext(addAgreement.Filename)
			baseName := filepath.Base(addAgreement.Filename[:len(addAgreement.Filename)-len(extension)])
			uniqueFileName := baseName + "_" + timestamp + extension
			absolutePath := filepath.Join(supplierFolderPath, uniqueFileName)
			if err := c.SaveUploadedFile(addAgreement, absolutePath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки доп. соглашения: " + err.Error()})
				return
			}
			addAgreementPath = &absolutePath
		}

		if disagreementProtocol != nil && (role == "curator" || role == "lawyer" || role == "admin") {
			extension := filepath.Ext(disagreementProtocol.Filename)
			baseName := filepath.Base(disagreementProtocol.Filename[:len(disagreementProtocol.Filename)-len(extension)])
			uniqueFileName := baseName + "_" + timestamp + extension
			absolutePath := filepath.Join(supplierFolderPath, uniqueFileName)
			if err := c.SaveUploadedFile(disagreementProtocol, absolutePath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки протокола разногласий: " + err.Error()})
				return
			}
			disagreementProtocolPath = &absolutePath
		}

		if lawyerEditedFile != nil && (role == "lawyer" || role == "admin") {
			extension := filepath.Ext(lawyerEditedFile.Filename)
			baseName := filepath.Base(lawyerEditedFile.Filename[:len(lawyerEditedFile.Filename)-len(extension)])
			uniqueFileName := generateFileName(baseName, lawyerFilePrefix, timestamp, extension)
			absolutePath := filepath.Join(supplierFolderPath, uniqueFileName)
			if err := c.SaveUploadedFile(lawyerEditedFile, absolutePath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки файла с правками юриста: " + err.Error()})
				return
			}
			lawyerEditedFilePath = &absolutePath
		}

		if chiefAccountantEditedFile != nil && (role == "chief_accountant" || role == "admin") {
			extension := filepath.Ext(chiefAccountantEditedFile.Filename)
			baseName := filepath.Base(chiefAccountantEditedFile.Filename[:len(chiefAccountantEditedFile.Filename)-len(extension)])
			uniqueFileName := generateFileName(baseName, chiefAccountantFilePrefix, timestamp, extension)
			absolutePath := filepath.Join(supplierFolderPath, uniqueFileName)
			if err := c.SaveUploadedFile(chiefAccountantEditedFile, absolutePath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки файла с правками главбуха: " + err.Error()})
				return
			}
			chiefAccountantEditedFilePath = &absolutePath
		}

		if signedFile != nil && (role == "curator" || role == "admin") {
			extension := filepath.Ext(signedFile.Filename)
			baseName := filepath.Base(signedFile.Filename[:len(signedFile.Filename)-len(extension)])
			uniqueFileName := baseName + "_signed_" + timestamp + extension
			absolutePath := filepath.Join(supplierFolderPath, uniqueFileName)
			if err := c.SaveUploadedFile(signedFile, absolutePath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки подписанного файла: " + err.Error()})
				return
			}
			signedFilePath = &absolutePath
		}

		contract := Contract{
			ID:                            id,
			Date:                          date,
			Number:                        number,
			Name:                          name,
			Supplier:                      supplier,
			Status:                        status,
			FilePath:                      filePath,
			AddAgreementPath:              addAgreementPath,
			DisagreementProtocolPath:      disagreementProtocolPath,
			LawyerEditedFilePath:          lawyerEditedFilePath,
			ChiefAccountantEditedFilePath: chiefAccountantEditedFilePath,
			History:                       current.History,
			Movement:                      movement,
			LawyerStatus:                  &lawyerStatus,
			ChiefAccountantStatus:         &chiefAccountantStatus,
			CounterpartyStatus:            &counterpartyStatus,
			Curator:                       curator,
			SignedFilePath:                signedFilePath,
			IsSignedElectronically:        isSignedElectronically,
		}

		if contract.Date == "" {
			contract.Date = current.Date
		}
		if contract.Number == "" {
			contract.Number = current.Number
		}
		if contract.Name == "" {
			contract.Name = current.Name
		}
		if contract.Supplier == "" {
			contract.Supplier = current.Supplier
		}
		if contract.Status == "" {
			contract.Status = current.Status
		}
		if contract.FilePath == nil {
			contract.FilePath = current.FilePath
		}
		if contract.AddAgreementPath == nil {
			contract.AddAgreementPath = current.AddAgreementPath
		}
		if contract.DisagreementProtocolPath == nil {
			contract.DisagreementProtocolPath = current.DisagreementProtocolPath
		}
		if contract.LawyerEditedFilePath == nil {
			contract.LawyerEditedFilePath = current.LawyerEditedFilePath
		}
		if contract.ChiefAccountantEditedFilePath == nil {
			contract.ChiefAccountantEditedFilePath = current.ChiefAccountantEditedFilePath
		}
		if contract.Movement == "" {
			contract.Movement = current.Movement
		}
		if contract.Curator == "" {
			contract.Curator = current.Curator
		}
		if contract.SignedFilePath == nil {
			contract.SignedFilePath = current.SignedFilePath
		}

		if contract.Status == "Проверка инициатором" && *contract.CounterpartyStatus != "Шаблон предоставлен" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Статус договора 'Проверка инициатором' возможен только после предоставления шаблона контрагентом."})
			return
		}

		if contract.Status == "СACACACсогласование внутри компании" {
			if *contract.CounterpartyStatus != "Шаблон предоставлен" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Согласование внутри компании возможно только после предоставления шаблона контрагентом."})
				return
			}
			if *contract.LawyerStatus == "Ожидает проверки" && *contract.ChiefAccountantStatus == "Ожидает проверки" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Для согласования внутри компании хотя бы один из участников (юрист или главбух) должен начать проверку."})
				return
			}
		}

		if contract.Status == "Согласование с контрагентом" {
			if *contract.LawyerStatus != "Согласовал" || *contract.ChiefAccountantStatus != "Согласовал" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Согласование с контрагентом возможно только после согласования юриста и главбуха."})
				return
			}
			if *contract.CounterpartyStatus == "Ожидает шаблон" || *contract.CounterpartyStatus == "Шаблон предоставлен" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Инициатор должен подтвердить, что договор передан контрагенту, и контрагент начал проверку."})
				return
			}
		}

		if contract.Status == "Подписание" {
			if *contract.LawyerStatus != "Согласовал" || *contract.ChiefAccountantStatus != "Согласовал" || *contract.CounterpartyStatus != "Согласовал" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Подписание возможно только после согласования всеми сторонами."})
				return
			}
		}

		if contract.Status == "Исполнение" || contract.Status == "Завершен" {
			if *contract.LawyerStatus != "Согласовал" || *contract.ChiefAccountantStatus != "Согласовал" || *contract.CounterpartyStatus != "Согласовал" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Исполнение или завершение возможно только после согласования всеми сторонами."})
				return
			}
		}

		if contract.Status == "Завершен" {
			if !contract.IsSignedElectronically && contract.SignedFilePath == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Для завершения договора необходимо либо прикрепить скан подписанного документа, либо отметить подписание по ЭДО"})
				return
			}
		}

		if contract.Status != current.Status && contract.Status != "" {
			newEntry := time.Now().Format("02.01.2006 15:04") + " - Статус изменен на '" + contract.Status + "'"
			if contract.History == "" {
				contract.History = newEntry
			} else {
				contract.History = newEntry + "\n" + contract.History
			}
		}

		_, err = db.Exec(
			"UPDATE contracts SET date = ?, number = ?, name = ?, supplier = ?, status = ?, file_path = ?, add_agreement_path = ?, disagreement_protocol_path = ?, lawyer_edited_file_path = ?, chief_accountant_edited_file_path = ?, history = ?, movement = ?, lawyer_status = ?, chief_accountant_status = ?, counterparty_status = ?, curator = ?, signed_file_path = ?, is_signed_electronically = ? WHERE id = ?",
			contract.Date, contract.Number, contract.Name, contract.Supplier, contract.Status, contract.FilePath, contract.AddAgreementPath, contract.DisagreementProtocolPath, contract.LawyerEditedFilePath, contract.ChiefAccountantEditedFilePath, contract.History, contract.Movement, contract.LawyerStatus, contract.ChiefAccountantStatus, contract.CounterpartyStatus, contract.Curator, contract.SignedFilePath, contract.IsSignedElectronically, id,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления договора: " + err.Error()})
			return
		}
		c.JSON(http.StatusOK, contract)
	})

	// Остальные маршруты с добавлением middleware
	r.GET("/contracts", authMiddleware("curator", "lawyer", "chief_accountant", "chief_engineer", "admin"), func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		role, _ := c.Get("role")

		query := "SELECT id, date, number, name, supplier, status, file_path, add_agreement_path, disagreement_protocol_path, lawyer_edited_file_path, chief_accountant_edited_file_path, history, movement, lawyer_status, chief_accountant_status, counterparty_status, curator, signed_file_path, is_signed_electronically FROM contracts"
		var rows *sql.Rows
		var err error

		if role == "curator" {
			var userCurator string
			err = db.QueryRow(
				"SELECT surname || ' ' || name || ' ' || patronymic FROM curators WHERE user_id = ?",
				userID,
			).Scan(&userCurator)
			if err == sql.ErrNoRows {
				log.Printf("[DEBUG] Куратор с user_id %d не найден в таблице curators", userID)
				c.JSON(http.StatusOK, []Contract{})
				return
			}
			if err != nil {
				log.Printf("[ERROR] Ошибка при получении куратора для user_id %d: %v", userID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки куратора: " + err.Error()})
				return
			}
			log.Printf("[DEBUG] Куратор найден: %s", userCurator)
			query += " WHERE curator = ?"
			rows, err = db.Query(query, userCurator)
			if err != nil {
				log.Printf("[ERROR] Ошибка выполнения запроса для куратора %s: %v", userCurator, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка запроса к базе данных: " + err.Error()})
				return
			}
		} else {
			log.Printf("[DEBUG] Запрос договоров для роли %s без фильтрации по куратору", role)
			rows, err = db.Query(query)
			if err != nil {
				log.Printf("[ERROR] Ошибка выполнения запроса для роли %s: %v", role, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка запроса к базе данных: " + err.Error()})
				return
			}
		}

		defer rows.Close()

		var contracts []Contract
		for rows.Next() {
			var contract Contract
			err := rows.Scan(
				&contract.ID,
				&contract.Date,
				&contract.Number,
				&contract.Name,
				&contract.Supplier,
				&contract.Status,
				&contract.FilePath,
				&contract.AddAgreementPath,
				&contract.DisagreementProtocolPath,
				&contract.LawyerEditedFilePath,
				&contract.ChiefAccountantEditedFilePath,
				&contract.History,
				&contract.Movement,
				&contract.LawyerStatus,
				&contract.ChiefAccountantStatus,
				&contract.CounterpartyStatus,
				&contract.Curator,
				&contract.SignedFilePath,
				&contract.IsSignedElectronically,
			)
			if err != nil {
				log.Printf("[ERROR] Ошибка чтения данных договора: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения данных: " + err.Error()})
				return
			}
			contracts = append(contracts, contract)
		}

		log.Printf("[DEBUG] Возвращено %d договоров для роли %s", len(contracts), role)
		c.JSON(http.StatusOK, contracts)
	})

	r.GET("/counterparties", authMiddleware("curator", "lawyer", "chief_accountant", "chief_engineer", "admin"), func(c *gin.Context) {
		rows, err := db.Query("SELECT id, name FROM counterparties")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка запроса к базе данных: " + err.Error()})
			return
		}
		defer rows.Close()

		var counterparties []Counterparty
		for rows.Next() {
			var cp Counterparty
			err := rows.Scan(&cp.ID, &cp.Name)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения данных: " + err.Error()})
				return
			}
			counterparties = append(counterparties, cp)
		}
		c.JSON(http.StatusOK, counterparties)
	})

	r.PUT("/counterparties/:id", authMiddleware("curator", "admin", "chief_engineer"), func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}

		var counterparty Counterparty
		if err := c.BindJSON(&counterparty); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных: " + err.Error()})
			return
		}

		var existingID int
		err = db.QueryRow("SELECT id FROM counterparties WHERE id = ?", id).Scan(&existingID)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Контрагент не найден"})
			return
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки контрагента: " + err.Error()})
			return
		}

		_, err = db.Exec(`
			UPDATE counterparties SET 
				name = ?, inn = ?, kpp = ?, ogrn = ?, bik = ?, bank_name = ?, account_number = ?, 
				director_name = ?, director_phone = ?, manager_name = ?, manager_phone = ?, 
				legal_address = ?, physical_address = ?, comment = ?
			WHERE id = ?`,
			counterparty.Name, counterparty.INN, counterparty.KPP, counterparty.OGRN, counterparty.BIK,
			counterparty.BankName, counterparty.AccountNumber, counterparty.DirectorName,
			counterparty.DirectorPhone, counterparty.ManagerName, counterparty.ManagerPhone,
			counterparty.LegalAddress, counterparty.PhysicalAddress, counterparty.Comment, id,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления контрагента: " + err.Error()})
			return
		}
		c.JSON(http.StatusOK, counterparty)
	})

	r.GET("/counterparties/:id", authMiddleware("curator", "lawyer", "chief_accountant", "chief_engineer", "admin"), func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}

		var counterparty Counterparty
		err = db.QueryRow(`
			SELECT id, name, inn, kpp, ogrn, bik, bank_name, account_number, 
				director_name, director_phone, manager_name, manager_phone, 
				legal_address, physical_address, comment
			FROM counterparties
			WHERE id = ?
		`, id).Scan(
			&counterparty.ID, &counterparty.Name, &counterparty.INN, &counterparty.KPP, &counterparty.OGRN,
			&counterparty.BIK, &counterparty.BankName, &counterparty.AccountNumber,
			&counterparty.DirectorName, &counterparty.DirectorPhone, &counterparty.ManagerName,
			&counterparty.ManagerPhone, &counterparty.LegalAddress, &counterparty.PhysicalAddress,
			&counterparty.Comment,
		)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "Контрагент не найден"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка запроса к базе данных: " + err.Error()})
			}
			return
		}
		c.JSON(http.StatusOK, counterparty)
	})

	r.DELETE("/contracts/:id", authMiddleware("admin"), func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}

		result, err := db.Exec("DELETE FROM contracts WHERE id = ?", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления договора: " + err.Error()})
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Договор не найден"})
			return
		}
		c.Status(http.StatusOK)
	})

	r.PUT("/contracts/:id/clear-history", authMiddleware("admin"), func(c *gin.Context) {
		id := c.Param("id")
		stmt, err := db.Prepare("UPDATE contracts SET history = '' WHERE id = ?")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка подготовки запроса: " + err.Error()})
			return
		}
		defer stmt.Close()

		result, err := stmt.Exec(id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка выполнения запроса: " + err.Error()})
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки результата: " + err.Error()})
			return
		}
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Договор с таким ID не найден"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "История очищена"})
	})

	r.GET("/download/:id/:filetype", authMiddleware("curator", "lawyer", "chief_accountant", "chief_engineer", "admin"), func(c *gin.Context) {
		idStr := c.Param("id")
		fileType := c.Param("filetype")
		userID, _ := c.Get("user_id")
		role, _ := c.Get("role")

		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}

		var contractCurator string
		err = db.QueryRow("SELECT curator FROM contracts WHERE id = ?", id).Scan(&contractCurator)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Договор не найден"})
			return
		}

		if role == "curator" {
			var userCurator string
			err = db.QueryRow(
				"SELECT surname || ' ' || name || ' ' || patronymic FROM users WHERE id = ?",
				userID,
			).Scan(&userCurator)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки куратора: " + err.Error()})
				return
			}
			if contractCurator != userCurator {
				c.JSON(http.StatusForbidden, gin.H{"error": "Куратор может скачивать файлы только своих договоров"})
				return
			}
		}

		var filePath *string
		var columnName string
		switch fileType {
		case "file", "add_agreement", "disagreement_protocol", "signed_file":
			if role != "curator" && role != "admin" && !(role == "lawyer" && fileType == "disagreement_protocol") {
				c.JSON(http.StatusForbidden, gin.H{"error": "Недостаточно прав для скачивания этого файла"})
				return
			}
			columnName = fileType + "_path"
		case "lawyer_edited":
			if role != "lawyer" && role != "admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Только юрист или админ могут скачивать этот файл"})
				return
			}
			columnName = "lawyer_edited_file_path"
		case "chief_accountant_edited":
			if role != "chief_accountant" && role != "admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Только главбух или админ могут скачивать этот файл"})
				return
			}
			columnName = "chief_accountant_edited_file_path"
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный тип файла"})
			return
		}

		err = db.QueryRow(
			fmt.Sprintf("SELECT %s FROM contracts WHERE id = ?", columnName),
			id,
		).Scan(&filePath)
		if err != nil || filePath == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден"})
			return
		}

		if _, err := os.Stat(*filePath); os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Файл не существует на сервере"})
			return
		}

		fileName := filepath.Base(*filePath)
		encodedFileName := encodeRFC5987(fileName)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", encodedFileName))
		c.Header("Content-Type", "application/octet-stream")
		c.File(*filePath)
	})

	r.DELETE("/delete-file/:id/:filetype", authMiddleware("curator", "lawyer", "chief_accountant", "admin"), func(c *gin.Context) {
		idStr := c.Param("id")
		fileType := c.Param("filetype")
		userID, _ := c.Get("user_id")
		role, _ := c.Get("role")

		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}

		var contractCurator string
		err = db.QueryRow("SELECT curator FROM contracts WHERE id = ?", id).Scan(&contractCurator)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Договор не найден"})
			return
		}

		if role == "curator" {
			var userCurator string
			err = db.QueryRow(
				"SELECT surname || ' ' || name || ' ' || patronymic FROM users WHERE id = ?",
				userID,
			).Scan(&userCurator)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки куратора: " + err.Error()})
				return
			}
			if contractCurator != userCurator {
				c.JSON(http.StatusForbidden, gin.H{"error": "Куратор может удалять файлы только своих договоров"})
				return
			}
		}

		var columnName string
		switch fileType {
		case "file", "add_agreement", "signed_file":
			if role != "curator" && role != "admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Только куратор или админ могут удалять этот файл"})
				return
			}
			columnName = fileType + "_path"
		case "disagreement_protocol":
			if role != "curator" && role != "lawyer" && role != "admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Только куратор, юрист или админ могут удалять этот файл"})
				return
			}
			columnName = "disagreement_protocol_path"
		case "lawyer_edited":
			if role != "lawyer" && role != "admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Только юрист или админ могут удалять этот файл"})
				return
			}
			columnName = "lawyer_edited_file_path"
		case "chief_accountant_edited":
			if role != "chief_accountant" && role != "admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Только главбух или админ могут удалять этот файл"})
				return
			}
			columnName = "chief_accountant_edited_file_path"
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный тип файла"})
			return
		}

		var filePath *string
		err = db.QueryRow(
			fmt.Sprintf("SELECT %s FROM contracts WHERE id = ?", columnName),
			id,
		).Scan(&filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка запроса к базе данных: " + err.Error()})
			return
		}
		if filePath == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "В базе данных нет пути к файлу"})
			return
		}

		normalizedPath := filepath.Clean(*filePath)
		if _, err := os.Stat(normalizedPath); !os.IsNotExist(err) {
			if err := os.Remove(normalizedPath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить файл с диска: " + err.Error()})
				return
			}
		}

		_, err = db.Exec(
			fmt.Sprintf("UPDATE contracts SET %s = NULL WHERE id = ?", columnName),
			id,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления базы данных: " + err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Файл успешно удалён"})
	})

	r.GET("/curators", authMiddleware("curator", "admin", "chief_engineer"), func(c *gin.Context) {
		rows, err := db.Query("SELECT id, surname, name, patronymic FROM curators")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка запроса к базе данных: " + err.Error()})
			return
		}
		defer rows.Close()

		var curators []struct {
			ID         int    `json:"id"`
			Surname    string `json:"surname"`
			Name       string `json:"name"`
			Patronymic string `json:"patronymic"`
		}
		for rows.Next() {
			var curator struct {
				ID         int    `json:"id"`
				Surname    string `json:"surname"`
				Name       string `json:"name"`
				Patronymic string `json:"patronymic"`
			}
			err := rows.Scan(&curator.ID, &curator.Surname, &curator.Name, &curator.Patronymic)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения данных: " + err.Error()})
				return
			}
			curators = append(curators, curator)
		}
		c.JSON(http.StatusOK, curators)
	})

	r.POST("/curators", authMiddleware("admin"), func(c *gin.Context) {
		var curator struct {
			Surname    string `json:"surname"`
			Name       string `json:"name"`
			Patronymic string `json:"patronymic"`
			UserID     int    `json:"user_id"`
		}
		if err := c.BindJSON(&curator); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
			return
		}
		if curator.Surname == "" || curator.Name == "" || curator.Patronymic == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Все поля (фамилия, имя, отчество) обязательны"})
			return
		}

		var userRole string
		err := db.QueryRow("SELECT role FROM users WHERE id = ?", curator.UserID).Scan(&userRole)
		if err != nil || userRole != "curator" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Указанный пользователь не является куратором"})
			return
		}

		result, err := db.Exec("INSERT INTO curators (surname, name, patronymic, user_id) VALUES (?, ?, ?, ?)", curator.Surname, curator.Name, curator.Patronymic, curator.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка добавления куратора: " + err.Error()})
			return
		}
		id, _ := result.LastInsertId()
		c.JSON(http.StatusOK, gin.H{"id": id, "surname": curator.Surname, "name": curator.Name, "patronymic": curator.Patronymic})
	})

	r.DELETE("/curators/:id", authMiddleware("admin"), func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}
		var contractCount int
		err = db.QueryRow("SELECT COUNT(*) FROM contracts WHERE curator = (SELECT surname || ' ' || name || ' ' || patronymic FROM curators WHERE id = ?)", id).Scan(&contractCount)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки договоров: " + err.Error()})
			return
		}
		if contractCount > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Нельзя удалить куратора, у которого есть связанные договоры"})
			return
		}
		result, err := db.Exec("DELETE FROM curators WHERE id = ?", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления куратора: " + err.Error()})
			return
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Куратор не найден"})
			return
		}
		c.Status(http.StatusOK)
	})

	r.POST("/users/check-login", authMiddleware("admin"), func(c *gin.Context) {
		var input struct {
			Login string `json:"login"`
		}
		if err := c.BindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
			return
		}

		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE login = ?", input.Login).Scan(&count)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки логина: " + err.Error()})
			return
		}

		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "Логин уже существует"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Логин доступен"})
	})

	// Новый маршрут: Получение списка пользователей
	r.GET("/users", authMiddleware("admin"), func(c *gin.Context) {
		rows, err := db.Query(`
			SELECT id, login, role, surname, name, patronymic
			FROM users
		`)
		if err != nil {
			log.Printf("[ERROR] Ошибка запроса списка пользователей: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка запроса к базе данных: " + err.Error()})
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var user User
			err := rows.Scan(&user.ID, &user.Login, &user.Role, &user.Surname, &user.Name, &user.Patronymic)
			if err != nil {
				log.Printf("[ERROR] Ошибка чтения данных пользователя: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения данных: " + err.Error()})
				return
			}
			users = append(users, user)
		}

		log.Printf("[DEBUG] Возвращено %d пользователей", len(users))
		c.JSON(http.StatusOK, users)
	})

	// Новый маршрут: Получение данных пользователя по ID
	r.GET("/users/:id", authMiddleware("admin"), func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}

		var user User
		err = db.QueryRow(`
			SELECT id, login, role, surname, name, patronymic
			FROM users
			WHERE id = ?
		`, id).Scan(&user.ID, &user.Login, &user.Role, &user.Surname, &user.Name, &user.Patronymic)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
			} else {
				log.Printf("[ERROR] Ошибка запроса пользователя ID %d: %v", id, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка запроса к базе данных: " + err.Error()})
			}
			return
		}

		c.JSON(http.StatusOK, user)
	})

	// Новый маршрут: Обновление данных пользователя
	r.PUT("/users/:id", authMiddleware("admin"), func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}

		var updatedUser User
		if err := c.BindJSON(&updatedUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных: " + err.Error()})
			return
		}

		// Проверка обязательных полей
		if updatedUser.Login == "" || updatedUser.Role == "" || updatedUser.Surname == "" || updatedUser.Name == "" || updatedUser.Patronymic == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Все поля (логин, роль, фамилия, имя, отчество) обязательны"})
			return
		}

		// Проверка существования пользователя
		var existingID int
		err = db.QueryRow("SELECT id FROM users WHERE id = ?", id).Scan(&existingID)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
			return
		} else if err != nil {
			log.Printf("[ERROR] Ошибка проверки пользователя ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки пользователя: " + err.Error()})
			return
		}

		// Проверка уникальности логина (если логин изменяется)
		var loginCount int
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE login = ? AND id != ?", updatedUser.Login, id).Scan(&loginCount)
		if err != nil {
			log.Printf("[ERROR] Ошибка проверки уникальности логина: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки логина: " + err.Error()})
			return
		}
		if loginCount > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "Логин уже используется другим пользователем"})
			return
		}

		// Обновление данных пользователя
		query := "UPDATE users SET login = ?, role = ?, surname = ?, name = ?, patronymic = ?"
		args := []interface{}{updatedUser.Login, updatedUser.Role, updatedUser.Surname, updatedUser.Name, updatedUser.Patronymic}

		// Если передан новый пароль, хэшируем его
		if updatedUser.Password != "" {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updatedUser.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Printf("[ERROR] Ошибка хэширования пароля: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка хэширования пароля"})
				return
			}
			query += ", password_hash = ?"
			args = append(args, string(hashedPassword))
		}

		query += " WHERE id = ?"
		args = append(args, id)

		_, err = db.Exec(query, args...)
		if err != nil {
			log.Printf("[ERROR] Ошибка обновления пользователя ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления пользователя: " + err.Error()})
			return
		}

		// Если пользователь - куратор, обновляем таблицу curators
		if updatedUser.Role == "curator" {
			var curatorCount int
			err = db.QueryRow("SELECT COUNT(*) FROM curators WHERE user_id = ?", id).Scan(&curatorCount)
			if err != nil {
				log.Printf("[ERROR] Ошибка проверки куратора для пользователя ID %d: %v", id, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки куратора: " + err.Error()})
				return
			}
			if curatorCount > 0 {
				_, err = db.Exec(
					"UPDATE curators SET surname = ?, name = ?, patronymic = ? WHERE user_id = ?",
					updatedUser.Surname, updatedUser.Name, updatedUser.Patronymic, id,
				)
			} else {
				_, err = db.Exec(
					"INSERT INTO curators (surname, name, patronymic, user_id) VALUES (?, ?, ?, ?)",
					updatedUser.Surname, updatedUser.Name, updatedUser.Patronymic, id,
				)
			}
			if err != nil {
				log.Printf("[ERROR] Ошибка обновления/добавления куратора для пользователя ID %d: %v", id, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления куратора: " + err.Error()})
				return
			}
		} else {
			// Если роль изменилась на не-куратор, удаляем из curators
			_, err = db.Exec("DELETE FROM curators WHERE user_id = ?", id)
			if err != nil {
				log.Printf("[ERROR] Ошибка удаления куратора для пользователя ID %d: %v", id, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления куратора: " + err.Error()})
				return
			}
		}

		log.Printf("[DEBUG] Пользователь ID %d успешно обновлен", id)
		c.JSON(http.StatusOK, gin.H{"message": "Пользователь успешно обновлен"})
	})

	// Новый маршрут: Удаление пользователя
	r.DELETE("/users/:id", authMiddleware("admin"), func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
			return
		}

		// Проверка, есть ли связанные договоры (для кураторов)
		var contractCount int
		err = db.QueryRow(`
			SELECT COUNT(*) 
			FROM contracts 
			WHERE curator = (SELECT surname || ' ' || name || ' ' || patronymic FROM users WHERE id = ?)
		`, id).Scan(&contractCount)
		if err != nil {
			log.Printf("[ERROR] Ошибка проверки договоров для пользователя ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки договоров: " + err.Error()})
			return
		}
		if contractCount > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Нельзя удалить пользователя, у которого есть связанные договоры"})
			return
		}

		// Удаление пользователя
		result, err := db.Exec("DELETE FROM users WHERE id = ?", id)
		if err != nil {
			log.Printf("[ERROR] Ошибка удаления пользователя ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления пользователя: " + err.Error()})
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
			return
		}

		// Удаление из curators, если пользователь был куратором
		_, err = db.Exec("DELETE FROM curators WHERE user_id = ?", id)
		if err != nil {
			log.Printf("[ERROR] Ошибка удаления куратора для пользователя ID %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления куратора: " + err.Error()})
			return
		}

		log.Printf("[DEBUG] Пользователь ID %d успешно удален", id)
		c.JSON(http.StatusOK, gin.H{"message": "Пользователь успешно удален"})
	})

	os.MkdirAll("D:\\contract\\Uploads", os.ModePerm)
	r.Static("/static", "./static")
	r.GET("/", func(c *gin.Context) {
		c.File("./static/contract.html")
	})

	const (
		green = "\033[32m"
		red   = "\033[31m"
		reset = "\033[0m"
	)

	fmt.Println(green + "🚀 Backend успешно запущен на http://localhost:8080" + reset)
	if err := r.Run("0.0.0.0:8080"); err != nil {
		fmt.Println(red + "❌ Ошибка запуска сервера: " + err.Error() + reset)
	}
}

func isColumnExistsError(err error) bool {
	return strings.Contains(err.Error(), "duplicate column name")
}
