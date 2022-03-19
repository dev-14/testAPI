package middleware

import (
	"testAPI/controllers"
	"testAPI/models"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

// the jwt middleware

func GetAuthMiddleware() (*jwt.GinJWTMiddleware, error) {
	var identityKey = "email"
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour,
		Authenticator: controllers.Login,
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if _, ok := data.(*models.User); ok {
				return true
			}
			return false
		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*models.User); ok {
				return jwt.MapClaims{identityKey: v.Email}
			}
			return jwt.MapClaims{}
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{"code": code, "message": message})
		},
		LoginResponse: func(c *gin.Context, code int, message string, time time.Time) {
			c.JSON(code, gin.H{
				"message": message,
			})
		},
		LogoutResponse: func(c *gin.Context, code int) {
			c.JSON(code, gin.H{"message": "logged out succesfully"})
		},
		RefreshResponse: func(c *gin.Context, code int, message string, time time.Time) {
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &models.User{Email: claims[identityKey].(string)}
		},
		IdentityKey:          identityKey,
		TokenLookup:          "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:        "Bearer",
		TimeFunc:             time.Now,
		PrivKeyFile:          "",
		PrivKeyBytes:         []byte{},
		PubKeyFile:           "",
		PrivateKeyPassphrase: "",
		PubKeyBytes:          []byte{},
		SendCookie:           false,
		CookieMaxAge:         0,
		SecureCookie:         false,
		CookieHTTPOnly:       false,
		CookieDomain:         "",
		SendAuthorization:    false,
		DisabledAbort:        false,
		CookieName:           "",
		CookieSameSite:       0,
	})
	if err != nil {
		return nil, err
	}
	return authMiddleware, nil
}
