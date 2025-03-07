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
	"github.com/kartik7120/booking_auth_service/cmd/models"
	"golang.org/x/crypto/bcrypt"
)

type Authentication struct {
	timeout time.Duration
	DB      *helper.DBConfig
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

func (a *Authentication) Register(user models.User) (string, int, error) {

	err := godotenv.Load()

	if err != nil {
		return "", 500, err
	}

	err = validate.Struct(user)

	if err != nil {
		return "", 400, err
	}

	if user.Username == "" || user.Email == "" || user.Password == "" {
		errString := "username, email and password are required fields"
		return "", 400, errors.New(errString)
	}

	// Check if a user with the same username is present in the database

	result := a.DB.Conn.Table("users").First(&models.User{
		Username: user.Username,
	})

	if result.Error != nil {
		return "", 500,
			result.Error
	}

	// extract columns from the result
	_, ok := result.Get("username")

	if ok {
		errString := "user with the same username already exists"
		return "", 403, errors.New(errString)
	}

	// if user is present then sent an error message that user cannot be created as a user with the same username already exists

	keyBase64 := os.Getenv("JWT_KEY_BASE64")
	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", 500, err
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
		return "", 500, err
	}

	// hash the password field of the user using bcrypt

	hashedPassword, err := helper.HashPassword(user.Password)

	if err != nil {
		return "", 500, err
	}

	// Add user to the database

	result = a.DB.Conn.Table("users").Create(&models.User{
		Username: user.Username,
		Email:    user.Email,
		Password: string(hashedPassword),
		Role:     "USER",
	})

	if result.Error != nil {
		return "", 500, result.Error
	}

	return s, 200, nil
}

func (a *Authentication) Login(user models.LoginUser) (string, int, error) {

	err := godotenv.Load()

	if err != nil {
		return "", 500, err
	}

	err = validate.Struct(user)

	if err != nil {
		return "", 400, err
	}

	if user.Username == "" || user.Password == "" {
		errString := "username and password are required fields"
		return "", 400, errors.New(errString)
	}

	// Check if a user with the same username is present in the database

	result := a.DB.Conn.Table("users").First(&models.User{
		Username: user.Username,
	})

	if result.Error != nil {
		return "", 500, result.Error
	}

	// Get user

	password, ok := result.Get("password")

	if !ok {
		errString := "user does not exist"
		return "", 404, errors.New(errString)
	}

	// convert password from interface{} to string

	password, ok = password.(string)

	if !ok {
		errString := "password is not a string"
		return "", 500, errors.New(errString)
	}

	// extract password field from the result and compare it with the password field of the user

	// if the password does not match then return an error message

	err = bcrypt.CompareHashAndPassword([]byte(password.(string)), []byte(user.Password))

	if err != nil {
		errString := "password does not match"
		return "", 403, errors.New(errString)
	}

	// if the password matches then generate a jwt token and return it

	keyBase64 := os.Getenv("JWT_KEY_BASE64")

	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)

	if err != nil {
		return "", 500, err
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
		return "", 500, err
	}

	return s, 200, nil
}

func (a *Authentication) ValidateToken(token string) (bool, int, error) {

	keyBase64 := os.Getenv("JWT_KEY_BASE64")

	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)

	if err != nil {
		return false, 500, err
	}

	key = keyBytes

	t, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithAudience("auth-service"), jwt.WithIssuer("auth-service"), jwt.WithSubject("user"), jwt.WithExpirationRequired())

	if err != nil {
		return false, 403, err
	}

	if t.Valid {
		return true, 200, nil
	}

	return false, 403, nil
}

func (a *Authentication) SendResetPasswordMail(email string) (int, error) {

	// check if the email is valid

	err := validate.Var(email, "email")

	if err != nil {
		return 400, err
	}

	// check if the email is present in the database

	result := a.DB.Conn.Table("users").First(&models.User{
		Email: email,
	})

	if result.Error != nil {
		return 500, result.Error
	}

	// send the user a email with a link to reset the password

	err = helper.SendMail(
		email,
		"Reset Password",
		"Please click on the link to reset your password",
		"",
		"reset-password",
		"Reset Password",
	)

	if err != nil {
		return 500, err
	}

	return 200, nil
}

func (a *Authentication) ResetPassword(user models.User, newPassword string) (int, error) {

	// validate newPassword string

	err := validate.Var(newPassword, "alphanum")

	if err != nil {
		return 400, err
	}

	// hash the newPassword string

	hashedPassword, err := helper.HashPassword(newPassword)

	if err != nil {
		return 500, err
	}

	// update the password field of the user in the database

	result := a.DB.Conn.Table("users").Where("email = ?", user.Email).Update("password", string(hashedPassword))

	if result.Error != nil {
		return 500, result.Error
	}

	return 200, nil
}
