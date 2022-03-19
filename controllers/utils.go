package controllers

import (
	"crypto/rand"
	"errors"
	"net/smtp"
	"strings"
	"testAPI/models"
	"unicode"

	"fmt"
	"log"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func IsPasswordStrong(password string) (bool, error) {
	var IsLength, IsUpper, IsLower, IsNumber, IsSpecial bool

	if len(password) < 6 {
		return false, errors.New("Password Length should be more then 6")
	}
	IsLength = true

	for _, v := range password {
		switch {
		case unicode.IsNumber(v):
			IsNumber = true

		case unicode.IsUpper(v):
			IsUpper = true

		case unicode.IsLower(v):
			IsLower = true

		case unicode.IsPunct(v) || unicode.IsSymbol(v):
			IsSpecial = true

		}
	}

	if IsLength && IsLower && IsUpper && IsNumber && IsSpecial {
		return true, nil
	}

	return false, errors.New("Password validation failed.")

}

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 8)
	if err != nil {
		log.Fatal("Error in Hashing")
		return "", err
	}
	return string(hashedPassword), err
}

// DoesUserExist is a helper function which checks if the user already exists in the user table or not.
func DoesUserExist(username string) bool {
	var users []models.User

	flag := strings.Index(username, "@")

	if flag == -1 {
		fmt.Println("mobile me aaya")
		err := models.DB.Where("mobile=?", username).First(&users).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return false
			}
		}
	} else {
		fmt.Println("email me aaya")
		err := models.DB.Where("email=?", username).First(&users).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return false
			}
		}
	}

	return true
}

// func DoesProductExist(ID int) bool {
// 	var product []models.Book
// 	err := models.DB.Where("id=?", ID).First(&product).Error
// 	if err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return false
// 		}
// 	}
// 	return true
// }

func CheckCredentials(username, userpassword string, db *gorm.DB) bool {
	// db := c.MustGet("db").(*gorm.DB)
	// var db *gorm.DB
	var User models.User
	// Store user supplied password in mem map
	var expectedpassword string
	var err error
	flag := strings.Index(username, "@")
	if flag == -1 {
		err = db.Where("mobile = ?", username).First(&User).Error
	} else {
		err = db.Where("email = ?", username).First(&User).Error
	}
	// check if the email exists
	// err := db.Where("email = ?", username).First(&User).Error

	if err == nil {
		// User Exists...Now compare his password with our password
		expectedpassword = User.Password
		if err = bcrypt.CompareHashAndPassword([]byte(expectedpassword), []byte(userpassword)); err != nil {
			// If the two passwords don't match, return a 401 status
			log.Println("User is Not Authorized")
			return false
		}
		// User is AUthenticates, Now set the JWT Token
		fmt.Println("User Verified")
		return true
	} else {
		// returns an empty array, so simply pass as not found, 403 unauth
		log.Fatal("ERR ", err)

	}
	return false
}

func NewRedisCache(c *gin.Context, user models.User) {
	//fmt.Println("setCache hit")
	c.Set("user_email", user.Email)
	fmt.Println(c.GetString("user_email"))
	if Flag == "email" {
		models.Rdb.HSet("user", "username", user.Email)
	} else {
		models.Rdb.HSet("user", "username", user.Mobile)
	}

	models.Rdb.HSet("user", "ID", user.ID)
	models.Rdb.HSet("user", "RoleID", user.UserRoleID)
	fmt.Println(models.Rdb.HGetAll("user").Result())
}

// func deleteRedis(c *gin.Context, user) {
// 	models.Rdb.Del(user.Email)
// 	fmt.Println("Redis Cleared")
// }

func IsAdmin(c *gin.Context) bool {
	// claims := jwt.ExtractClaims(c)
	// user_email, _ := claims["email"]
	var User models.User
	// email := c.GetString("user_email")
	user_email, _ := models.Rdb.HGet("user", "email").Result()
	fmt.Println(models.Rdb.HGetAll("user"))

	// Check if the current user had admin role.
	if err := models.DB.Where("email = ? AND user_role_id=1", user_email).First(&User).Error; err != nil {
		return false
	}
	return true
}

func IsSupervisor(c *gin.Context) bool {
	// claims := jwt.ExtractClaims(c)
	// user_email, _ := claims["email"]
	var User models.User
	user_email, _ := models.Rdb.HGet("user", "username").Result()
	fmt.Println(user_email)
	// fmt.Println(user_email)
	// Check if the current user had admin role.
	if err := models.DB.Where("email = ? AND user_role_id=2", user_email).First(&User).Error; err != nil {
		return false
	}
	return true
}

func FillRedis(c *gin.Context) error {
	var User models.User
	claims := jwt.ExtractClaims(c)
	email := claims["email"]

	err := models.DB.Where("email = ? ", email).First(&User).Error
	if err != nil {
		return err
	}
	NewRedisCache(c, User)
	return nil
}

func IsAuthorized(username string) bool {
	var User models.User
	fmt.Println(Flag)
	if Flag == "email" {
		if err := models.DB.Where("email = ?", username).First(&User).Error; err != nil {
			// c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return false
		}
	} else {
		if err := models.DB.Where("mobile = ?", username).First(&User).Error; err != nil {
			// c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return false
		}
	}
	return true
}

func SendEmail(c *gin.Context, user models.User) {
	otp, _ := rand.Prime(rand.Reader, 32)
	fmt.Println(otp)

	// Message.
	m := fmt.Sprintf("Authentication otp is %v", otp)

	message := []byte(m)
	auth := smtp.PlainAuth("", models.FromEmail, models.PassEmail, models.SmtpHost)
	to := []string{user.Email}
	// Sending email.
	err := smtp.SendMail(models.SmtpHost+":"+models.SmtpPort, auth, models.FromEmail, to, message)
	if err != nil {
		fmt.Println(err)
		return
	}
	models.Rdb.HSet("verify", "user", user.Email)
	models.Rdb.HSet("verify", "otp", otp)
}
