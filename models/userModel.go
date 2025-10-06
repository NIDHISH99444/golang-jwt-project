package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `bson:"_id"`
	FirstName    *string            `json:"first_name" validation:"required,min=2, max=100"`
	LastName     *string            `json:"last_name" validation:"required,min=2, max=100"`
	Password     *string            `json:"Password"`
	Email        *string            `json:"email" validation:"email, required"`
	Phone        *string            `json:"phone" validation:"required"`
	Token        *string            `json:"token"`
	UserType     *string            `json:"user_type" validation:"required , eq= ADMIN| eq=USER"`
	RefreshToken *string            `json:"refresh_token"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updted_at"`
	UserId       string             `json:"user_id"`
}
