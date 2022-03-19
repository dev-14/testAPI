package main

import (
	//"net/http"

	"fmt"
	"os"
	_ "testAPI/docs"
	"testAPI/models"
	"testAPI/routes"

	"github.com/gin-gonic/gin"
	//jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/joho/godotenv"
)

// @title Login System
// @version 1.0
// @Description Golang basic API.
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @contact.email
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8080
// @BasePath /
func main() {
	// r := gin.Default()
	godotenv.Load()          // Load env variables
	models.ConnectDataBase() // load db
	var router = make(chan *gin.Engine)
	go routes.GetRouter(router)
	var port string = os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}
	server_addr := fmt.Sprintf(":%s", port)
	r := <-router
	r.Run(server_addr)
}
