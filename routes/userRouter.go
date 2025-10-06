package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/nidhish/golang-jwt-project/controllers"
	"github.com/nidhish/golang-jwt-project/middleware"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("/users/:user_id", controllers.GetUser())
}
