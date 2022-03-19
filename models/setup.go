package models

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	//"github.com/jinzhu/gorm"
	"github.com/go-redis/redis"
	//_ "github.com/lib/pq"
)

var DB *gorm.DB
var Rdb *redis.Client

var SmtpHost string
var SmtpPort string
var FromEmail string
var PassEmail string

type Settings struct {
	DB_HOST     string
	DB_NAME     string
	DB_USER     string
	DB_PASSWORD string
	DB_PORT     string
}

func InitializeSettings() Settings {
	DB_HOST := os.Getenv("DB_HOST")
	DB_NAME := os.Getenv("DB_NAME")
	DB_USER := os.Getenv("DB_USER")
	DB_PASSWORD := os.Getenv("DB_PASSWORD")
	DB_PORT := os.Getenv("DB_PORT")
	SMTP_HOST := os.Getenv("SMTP_HOST")
	SMTP_PASS := os.Getenv("SMTP_PASS")
	SMTP_PORT := os.Getenv("SMTP_PORT")

	var addr = os.Getenv("REDIS_PORT")
	var pass = os.Getenv("REDIS_PASSWORD")
	db, _ := strconv.Atoi(os.Getenv("REDIS_DB"))

	fmt.Println(addr, pass, db)
	Rdb = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: pass, // no password set
		DB:       db,   // use default DB
	})

	FromEmail = SMTP_HOST
	PassEmail = SMTP_PASS

	// // Receiver email address.
	// to := []string{
	// 	"example@gmail.com",
	// }

	// smtp server configuration.
	SmtpHost = "smtp.gmail.com"
	SmtpPort = SMTP_PORT

	switch {
	case DB_HOST == "":
		fmt.Println("1 Environmet variable DB_HOST not set.")
		os.Exit(1)
	case DB_NAME == "":
		fmt.Println("Environmet variable DB_NAME not set.")
		os.Exit(1)
	case DB_USER == "":
		fmt.Println("Environmet variable DB_USER not set.")
		os.Exit(1)
	case DB_PASSWORD == "":
		fmt.Println("Environmet variable DB_PASSWORD not set.")
		os.Exit(1)
	}

	settings := Settings{
		DB_HOST:     DB_HOST,
		DB_NAME:     DB_NAME,
		DB_USER:     DB_USER,
		DB_PASSWORD: DB_PASSWORD,
		DB_PORT:     DB_PORT,
	}

	return settings
}

func createInitialData() {

	var UserRoles = []UserRole{
		{
			Id:   1,
			Role: "admin",
		},
		{
			Id:   2,
			Role: "supervisor",
		},
		{
			Id:   3,
			Role: "customer",
		},
	}

	err := DB.CreateInBatches(UserRoles, 3).Error
	if err != nil {
		fmt.Println("user roles created successfully")
	}
	encryptedPassword, _ := bcrypt.GenerateFromPassword([]byte("SuperPassword@123"), 8)
	// var test string
	err = DB.Select("id", "first_name", "last_name", "email", "user_role_id", "password").Create(
		&User{
			ID:         1,
			FirstName:  "admin",
			LastName:   "admin",
			Email:      "admin@gmail.com",
			UserRoleID: 1,
			Password:   string(encryptedPassword),
		},
	).Error

	if err != nil {
		fmt.Println("Admin already exists")
	}
}

func ConnectDataBase() {
	// database := fmt.Sprintf("host=localhost port=5432 user=postgres dbname=postgres password=admin sslmode=disable")
	//database := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable", DB_HOST, DB_PORT, DB_USER, DB_NAME, DB_PASSWORD)
	settings := InitializeSettings()
	url := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=disable", settings.DB_USER, settings.DB_PASSWORD, settings.DB_HOST, settings.DB_PORT, settings.DB_NAME)
	// database := "host=" + settings.DB_HOST + " user=" + settings.DB_USER + " password=" + settings.DB_PASSWORD + " dbname=" + settings.DB_NAME + " port=" + settings.DB_PORT + " sslmode=disable"
	// fmt.Println("conname is\t", database)
	connection, err := gorm.Open(postgres.Open(url), &gorm.Config{})

	if err != nil {
		panic("Failed to connect to database!")
	}
	fmt.Println("Migrating tables")

	//tried migrating using interface
	// var models = []interface{}{&User{}, &UserRole{}, &Book{}, &Category{}}
	// connection.AutoMigrate(models...)

	//normal migration
	err = connection.AutoMigrate(&UserRole{}, &User{})
	if err != nil {
		fmt.Println("error in migration: ", err)
	}
	fmt.Println("Done migrating")

	//DB.Migrator().CreateTable(&Category{})
	DB = connection
	fmt.Println("Done migrating")
	//connection.AutoMigrate(&User{})

	createInitialData()
}
