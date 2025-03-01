// filepath: /home/kartik7120/booking_auth_service/cmd/auth/authentication.go
package auth

import (
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/kartik7120/booking_auth_service/cmd/helper"
	"golang.org/x/crypto/bcrypt"
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

type LoginUser struct {
	Username string `json:"username" validate:"required,alphanum"`
	Password string `json:"password" validate:"required,alphanum"`
}

var validate *validator.Validate

var (
	key []byte
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

	queryString := "SELECT * FROM users WHERE username = ?"

	result, err := a.DB.SelectDB(queryString, user.Username)

	if err != nil {
		return "", err
	}

	cols, err := result.Columns()

	if err != nil {
		return "", err
	}

	if len(cols) > 0 {
		errString := "user with the same username already exists"
		return "", errors.New(errString)
	}

	// if user is present then sent an error message that user cannot be created as a user with the same username already exists

	keyBase64 := os.Getenv("JWT_KEY_BASE64")
	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}

	key = keyBytes

	t = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.Username,
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
		"role": "user",
		"iss":  "auth-service",
	})

	s, err = t.SignedString(key)

	if err != nil {
		return "", err
	}

	// hash the password field of the user using bcrypt

	hashedPassword, err := helper.HashPassword(user.Password)

	if err != nil {
		return "", err
	}

	// Add user to the database

	queryString = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"

	_, err = a.DB.InsertDB(queryString, user.Username, user.Email, hashedPassword)

	if err != nil {
		return "", err
	}

	return s, err
}

func (a *Authentication) Login(user LoginUser) (string, error) {

	err := godotenv.Load()

	if err != nil {
		return "", err
	}

	err = validate.Struct(user)

	if err != nil {
		return "", err
	}

	if user.Username == "" || user.Password == "" {
		errString := "username and password are required fields"
		return "", errors.New(errString)
	}

	// Check if a user with the same username is present in the database

	queryString := "SELECT * FROM users WHERE username = ?"

	result, err := a.DB.SelectDB(queryString, user.Username)

	if err != nil {
		return "", err
	}

	cols, err := result.Columns()

	if err != nil {
		return "", err
	}

	if len(cols) == 0 {
		errString := "user does not exist"
		return "", errors.New(errString)
	}

	// extract password field from the result and compare it with the password field of the user

	// if the password does not match then return an error message

	password := "" // extract password from the result

	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(user.Password))

	if err != nil {
		errString := "password does not match"
		return "", errors.New(errString)
	}

	// if the password matches then generate a jwt token and return it

	keyBase64 := os.Getenv("JWT_KEY_BASE64")

	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)

	if err != nil {
		return "", err
	}

	key = keyBytes

	t = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.Username,
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
		"role": "user",
		"iss":  "auth-service",
	})

	s, err = t.SignedString(key)

	if err != nil {
		return "", err
	}

	return s, nil
}
