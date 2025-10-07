package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nidhish/golang-jwt-project/helpers"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1️⃣ Get token from request header
		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token not provided"})
			c.Abort()
			return
		}

		// 2️⃣ Validate the token using helper
		claims, msg := helpers.ValidateToken(clientToken)
		if msg != "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": msg})
			c.Abort()
			return
		}

		// 3️⃣ Inject claims into Gin context
		c.Set("email", claims.Email)
		c.Set("first_name", claims.FirstName)
		c.Set("last_name", claims.LastName)
		c.Set("uid", claims.Uid)
		c.Set("user_type", claims.UserType)

		// 4️⃣ Continue to next middleware/handler
		c.Next()
	}
}
