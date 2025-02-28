package auth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/kartik7120/booking_auth_service/cmd/helper"
)

type Authentication struct {
	timeout time.Duration
	DB      *helper.DBConfig
}

type User struct {
	Username string `json:"username" validate:"required,alphanum"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,alphanum"`
}

var validate *validator.Validate

var (
	key *ecdsa.PrivateKey
	t   *jwt.Token
	s   string
)

func NewAuthentication(timeout time.Duration) *Authentication {
	validate = validator.New()
	return &Authentication{
		timeout: timeout,
	}
}

func (a *Authentication) Register(user User) (string, error) {

	err := godotenv.Load()

	if err != nil {
		return "", err
	}

	err = validate.Struct(user)

	if err != nil {
		return "", err
	}

	if user.Username == "" || user.Email == "" || user.Password == "" {
		errString := "username, email and password are required fields"
		return "", errors.New(errString)
	}

	// Check if a user with the same username is present in the database

	queryString := fmt.Sprintf("SELECT * FROM users WHERE username = %s", user.Username)

	result, err := a.DB.SelectDB(queryString)

	if err != nil {
		return "", err
	}

	if result != nil {
		errString := "user with the same username already exists"
		return "", errors.New(errString)
	}

	// if user is present then sent an error message that user cannot be created as a user with the same username already exists

	key := os.Getenv("JWT_KEY")

	t = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":  user.Username,
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
		"role": "user",
		"iss":  "auth-service",
	})

	s, err = t.SignedString(key)

	if err != nil {
		return "", err
	}

	// if a user with the same username does not exists then we create a jwt token with the sub set to username of the user

	return s, err
}

func (a *Authentication) Login(user User) (string, error) {
	return "", nil
}
