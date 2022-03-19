package controllers

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"testAPI/models"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

const SecretKey = "secret"

var otp string

var Flag string

type tempUser struct {
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
	Email     string `json:"email" binding:"required"`
	Mobile    string `json:"mobile" binding:"required"`
	// Username        string `json:"username" binding:"required"`
	Password        string `json:"password" binding:"required"`
	ConfirmPassword string `json:"confirmpassword" binding:"required"`
}

func ReturnParameterMissingError(c *gin.Context, parameter string) {
	var err = fmt.Sprintf("Required parameter %s missing.", parameter)
	c.JSON(http.StatusBadRequest, gin.H{"error": err})
}

// @Summary register endpoint is used for customer registration. ( Supervisors/admin can be added only by admin. )
// @Description API Endpoint to register the user with the role of customer.
// @Router /api/v1/register [post]
// @Tags auth
// @Accept json
// @Produce json
// @Success 200
// @Param email formData string true "Email of the user"
// @Param first_name formData string true "First name of the user"
// @Param last_name formData string true "Last name of the user"
// @Param password formData string true "Password of the user"
// @Param confirm_password formData string true "Confirm password."
func Register(c *gin.Context) {
	var tempUser tempUser
	var Role models.UserRole

	c.Request.ParseForm()
	paramList := []string{"username", "first_name", "last_name", "password", "confirmpassword"}

	for _, param := range paramList {
		if c.PostForm(param) == "" {
			ReturnParameterMissingError(c, param)
		}
	}

	// if err := c.ShouldBindJSON(&tempUser); err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	// 	return
	// }

	tempUser.Email = template.HTMLEscapeString(c.PostForm("email"))
	tempUser.Mobile = template.HTMLEscapeString(c.PostForm("mobile"))
	tempUser.FirstName = template.HTMLEscapeString(c.PostForm("first_name"))
	tempUser.LastName = template.HTMLEscapeString(c.PostForm("last_name"))
	tempUser.Password = template.HTMLEscapeString(c.PostForm("password"))
	tempUser.ConfirmPassword = template.HTMLEscapeString(c.PostForm("confirmpassword"))

	if tempUser.Password != tempUser.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Both passwords do not match."})
		return
	}

	ispasswordstrong, _ := IsPasswordStrong(tempUser.Password)
	if !ispasswordstrong {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password is not strong."})
		return
	}

	// Check if the user already exists.
	if DoesUserExist(tempUser.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already exists."})
		return
	}
	if DoesUserExist(tempUser.Mobile) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already exists."})
		return
	}

	encryptedPassword, error := HashPassword(tempUser.Password)
	if error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Some error occoured."})
		return
	}

	err := models.DB.Where("role= ?", "customer").First(&Role).Error
	if err != nil {
		fmt.Println("err ", err.Error())
		return
	}

	// flag := strings.Index(tempUser.Username, "@")
	// if flag == -1 {
	fmt.Println(len([]rune(tempUser.Mobile)))
	if len([]rune(tempUser.Mobile)) != 10 {
		c.JSON(404, gin.H{
			"error": "Invalid Mobile Number",
		})
		return
	}
	// Flag = "mobile"
	SanitizedUser := models.User{
		FirstName:  tempUser.FirstName,
		LastName:   tempUser.LastName,
		Email:      tempUser.Email,
		Mobile:     tempUser.Mobile,
		Password:   encryptedPassword,
		UserRoleID: Role.Id, //This endpoint will be used only for customer registration.
		CreatedAt:  time.Now(),
		IsActive:   true,
	}
	errs := models.DB.Select("first_name", "last_name", "email", "mobile", "password", "user_role_id", "created_at", "is_active").Create(&SanitizedUser).Error
	if errs != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Some error occoured while input to db"})
		return
	}
	// } else {
	// Flag = "email"
	// SanitizedUser := models.User{
	// 	FirstName:  tempUser.FirstName,
	// 	LastName:   tempUser.LastName,
	// 	Email:      tempUser.Username,
	// 	Password:   encryptedPassword,
	// 	UserRoleID: Role.Id, //This endpoint will be used only for customer registration.
	// 	CreatedAt:  time.Now(),
	// 	IsActive:   false,
	// }
	// errs := models.DB.Select("first_name", "last_name", "email", "password", "user_role_id", "created_at", "is_active").Create(&SanitizedUser).Error
	// if errs != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Some error occoured while input to db"})
	// 	return
	// }
	// }

	c.JSON(http.StatusOK, gin.H{"msg": "User created successfully. To login, please activate user by verifying otp sent on email"})

}

func VerifyUser(c *gin.Context) {
	var user models.User
	user_email, _ := models.Rdb.HGet("verify", "user").Result()
	inputOTP, _ := models.Rdb.HGet("verify", "otp").Result()
	email := template.HTMLEscapeString(c.PostForm("email"))
	userOTP := template.HTMLEscapeString(c.PostForm("otp"))
	err := models.DB.Where("email = ?", email).First(&user).Error
	if err != nil || email != user_email {
		c.JSON(404, gin.H{
			"message": "email not found",
		})
		return
	}
	if userOTP != inputOTP {
		c.JSON(404, gin.H{
			"message": "invalid otp. Please try again",
		})
		return
	}
	user.IsActive = true
	c.JSON(200, gin.H{
		"message": "successfully verified user",
	})
}

type login struct {
	Email    string `form:"email" json:"email" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

// redisClient := Redis.createclient()

// Login godoc
// @Summary Login endpoint is used by the user to login.
// @Description API Endpoint to register the user with the role of customer.
// @Router /api/v1/login [post]
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 description {object}
// @Param email formData string true "email id"
// @Param password formData string true "password"
func Login(c *gin.Context) (interface{}, error) {
	// var loginVals login
	// var User User
	var user models.User
	var count int64

	username := template.HTMLEscapeString(c.PostForm("username"))
	password := template.HTMLEscapeString(c.PostForm("password"))

	flag := strings.Index(username, "@")

	if flag == -1 {
		Flag = "mobile"
		fmt.Println("mobile hai")

	} else {
		Flag = "email"
		fmt.Println("email hai")
	}
	// var user models.User
	// if err := c.ShouldBind(&loginVals); err != nil {
	// 	return "", jwt.ErrMissingLoginValues
	// }
	fmt.Println(Flag)
	// email := loginVals.Email
	// First check if the user exist or not...
	if Flag == "email" {
		models.DB.Where("email = ?", username).First(&user).Count(&count)
		if count == 0 {
			return nil, jwt.ErrFailedAuthentication
		}
		if !user.IsActive {
			SendEmail(c, user)
			c.JSON(404, gin.H{
				"message": "user is not activated. Check Email for activation.",
			})
			return nil, jwt.ErrFailedAuthentication
		}
	} else if Flag == "mobile" {
		models.DB.Where("mobile = ?", username).First(&user).Count(&count)
		if count == 0 {
			return nil, jwt.ErrFailedAuthentication
		}
	}
	if CheckCredentials(username, password, models.DB) {
		NewRedisCache(c, user)
		if Flag == "email" {
			return &models.User{
				Email: username,
			}, nil
		} else {
			return &models.User{
				Mobile: username,
			}, nil
		}

	}
	// fmt.Println("set value ", loginVals.Email)
	// err := rdb.Set("email", loginVals.Email, 0).Err()
	// if err != nil {
	// 	c.JSON(http.StatusNotFound, gin.H{
	// 		"error": "error in redis",
	// 	})
	// }

	return nil, jwt.ErrFailedAuthentication
}

func MyProfile(c *gin.Context) {
	var User models.User

	claims := jwt.ExtractClaims(c)

	user_email, _ := claims["email"]
	_ = user_email
	username := "user_useremail"
	// username, _ := models.Rdb.HGet("user", "username").Result()

	if username == "" {
		fmt.Println("Redis empty....checking Database for user...")
		err := FillRedis(c)
		if err != nil {
			c.JSON(404, gin.H{
				"error": "something went wrong with redis",
			})
			return
		}
	}
	username, _ = models.Rdb.HGet("user", "username").Result()

	if Flag == "email" {
		if err := models.DB.Where("email = ?", username).First(&User).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
	} else {
		if err := models.DB.Where("mobile = ?", username).First(&User).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
	}
	c.JSON(200, &User)

}
