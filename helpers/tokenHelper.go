package helpers

import (
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nidhish/golang-jwt-project/database"
	"go.mongodb.org/mongo-driver/mongo"
)

type SignedDetails struct {
	Email     string
	FirstName string
	LastName  string
	Uid       string
	UserType  string
	jwt.RegisteredClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string = os.Getenv("SECRET_KEY")

func GenerateAllTokens(email string, firstNme string, lastName string, userType string, uid string) (signedToken string, refreshSignedToken string, err error) {
	now := time.Now().UTC()
	claims := &SignedDetails{
		Email:     email,
		FirstName: firstNme,
		LastName:  lastName,
		UserType:  userType,
		Uid:       uid,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}

	refreshClaims := &SignedDetails{
		Email:     email,
		FirstName: firstNme,
		LastName:  lastName,
		UserType:  userType,
		Uid:       uid,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			// Optional: Issuer, Subject, Audience, ID...
		},
	}
	var refreshToken string
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err)
		return
	}

	return token, refreshToken, err

}
