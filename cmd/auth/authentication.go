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
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
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
	log.Info("Creating a new authentication instance")
	validate = validator.New()
	return &Authentication{
		timeout: timeout,
	}
}

func (a *Authentication) CheckUserExists(email string) (bool, int, error) {
	var user models.User

	err := a.DB.Conn.Model(models.User{}).Where("email = ?", email).First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, 200, nil
		}
		return false, 500, err
	}

	return true, 200, nil
}

func (a *Authentication) Register(user models.User) (string, int, error) {

	log.Info("Registering user")

	err := godotenv.Load()

	if err != nil {
		log.Error("Error loading .env file")
		return "", 500, err
	}

	u := &models.User{
		Email:    user.Email,
		Password: user.Password,
	}

	err = validate.Struct(u)

	if err != nil {
		log.Error("Error validating user")
		return "", 400, err
	}

	if user.Email == "" || user.Password == "" {
		log.WithFields(log.Fields{
			"email":    user.Email,
			"password": user.Password,
		}).Error("username, email and password are required fields")
		errString := "username, email and password are required fields"
		return "", 400, errors.New(errString)
	}

	// Check if a user with the same username is present in the database

	result := a.DB.Conn.Table("users").First(&models.User{
		Email: user.Email,
	})

	if result.Error.Error() == `ERROR: relation "users" does not exist (SQLSTATE 42P01)` {
		err := a.DB.Conn.Table("users").AutoMigrate(&models.User{})
		if err != nil {
			log.Error("Error creating table users")
			return "", 500, err
		}
		log.Info("Table users created successfully")
	}

	if result.Error.Error() == `record not found` {
		log.Info("No user with the same username found")
	} else {
		log.WithFields(log.Fields{
			"email": user.Email,
		}).Error("error checking if user exists")

		return "", 500,
			result.Error
	}

	// extract columns from the result
	_, ok := result.Get("email")

	if ok {
		log.WithFields(log.Fields{
			"email": user.Email,
		}).Error("user with the same email already exists")
		errString := "user with the same email already exists"
		return "", 403, errors.New(errString)
	}

	// if user is present then sent an error message that user cannot be created as a user with the same username already exists

	keyBase64 := os.Getenv("JWT_KEY_BASE64")
	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)

	if err != nil {
		log.Error("Error decoding base64 key")
		return "", 500, err
	}

	key = keyBytes

	t = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.Email,
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
		"role": "user",
		"iss":  "auth-service",
	})

	s, err = t.SignedString(key)

	if err != nil {
		log.Error("Error signing jwt token")
		return "", 500, err
	}

	// hash the password field of the user using bcrypt

	hashedPassword, err := helper.HashPassword(user.Password)

	if err != nil {
		log.Error("Error hashing password")
		return "", 500, err
	}

	// Add user to the database

	result = a.DB.Conn.Table("users").Create(&models.User{
		Email:    user.Email,
		Password: string(hashedPassword),
		Role:     "USER",
	})

	if result.Error != nil {
		log.Error("Error creating user in the database")
		return "", 500, result.Error
	}

	log.Info("User registered successfully")
	return s, 200, nil
}

func (a *Authentication) Login(user models.LoginUser) (string, int, error) {

	log.Info("Logging in user")
	err := godotenv.Load()

	if err != nil {
		log.Error("Error loading .env file")
		return "", 500, err
	}

	err = validate.Struct(&user)

	if err != nil {
		log.Error("Error validating user")
		return "", 400, err
	}

	if user.Email == "" || user.Password == "" {
		log.WithFields(log.Fields{
			"email":    user.Email,
			"password": user.Password,
		}).Error("username and password are required fields")
		errString := "username and password are required fields"
		return "", 400, errors.New(errString)
	}

	// Check if a user with the same username is present in the database

	result := a.DB.Conn.Table("users").Where("email = ?", user.Email).First(&models.User{})

	if result.Error != nil {
		log.WithFields(log.Fields{
			"Email": user.Email,
		}).Error("error checking if user exists")
		return "", 500, result.Error
	}

	// Get user

	userObj := models.User{
		// Username: user.Username,
		Email: user.Email,
	}

	row := a.DB.Conn.Table("users").Select("password").Where("Email = ?", user.Email).Row()
	err = row.Scan(&userObj.Password)

	if err != nil {
		log.Error("Error scanning user")
		return "", 500, err
	}

	if row.Err() != nil {
		log.WithFields(log.Fields{
			"email": user.Email,
		}).Error("user does not exist")
		errString := "user does not exist"
		return "", 404, errors.New(errString)
	}

	password := userObj.Password

	if len(password) == 0 {
		log.WithFields(log.Fields{
			"Email": user.Email,
		}).Error("password field is empty")
		errString := "password field is empty"
		return "", 500, errors.New(errString)
	}

	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(user.Password))

	if err != nil {
		log.Error("password does not match")
		errString := "password does not match"
		return "", 403, errors.New(errString)
	}

	// if the password matches then generate a jwt token and return it

	keyBase64 := os.Getenv("JWT_KEY_BASE64")

	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)

	if err != nil {
		log.Error("Error decoding base64 key")
		return "", 500, err
	}

	key = keyBytes

	t = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.Email,
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
		"role": "user",
		"iss":  "auth-service",
	})

	s, err = t.SignedString(key)

	if err != nil {
		log.Error("Error signing jwt token")
		return "", 500, err
	}

	log.Info("User logged in successfully")
	return s, 200, nil
}

func (a *Authentication) ValidateToken(token string) (bool, int, error) {

	log.Info("Validating token")

	keyBase64 := os.Getenv("JWT_KEY_BASE64")

	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)

	if err != nil {
		log.Error("Error decoding base64 key")
		return false, 500, err
	}

	key = keyBytes

	t, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithIssuer("auth-service"), jwt.WithExpirationRequired())

	if err != nil {
		log.Error("Error parsing jwt token")
		return false, 403, err
	}

	if t.Valid {
		log.Info("Token is valid")
		return true, 200, nil
	}

	log.Error("Token is invalid")
	return false, 403, nil
}

func (a *Authentication) SendResetPasswordMail(email string) (int, error) {

	// check if the email is valid

	log.Info("Sending reset password mail")

	err := validate.Var(&email, "email")

	if err != nil {
		log.Error("Error validating email")
		return 400, err
	}

	// check if the email is present in the database

	result := a.DB.Conn.Table("users").Where("email = ?", email).First(&models.User{})

	if result.Error != nil && result.Error.Error() == `record not found` {
		log.Info("User does not exist")
		errString := "user does not exist"
		return 404, errors.New(errString)
	}

	if result.Error != nil {
		log.WithFields(log.Fields{
			"email": email,
		}).Error("error checking if user exists")
		return 500, result.Error
	}

	// send the user a email with a link to reset the password

	err = helper.SendMail(
		email,            // to
		"Reset Password", // name
		"Please click on the link to reset your password", // text
		"",               // html
		"reset-password", // category
		"Reset Password", // subject
	)

	if err != nil {
		log.Error("Error sending reset password mail")
		return 500, err
	}

	log.Info("Reset password mail sent successfully")
	return 200, nil
}

func (a *Authentication) ResetPassword(user models.User, newPassword string) (int, error) {

	// validate newPassword string
	log.Info("Resetting password")
	err := validate.Var(&newPassword, "alphanum")

	if err != nil {
		log.Error("Error validating new password")
		return 400, err
	}

	result := a.DB.Conn.Table("users").Where(&models.User{
		Email: user.Email,
	}).First(&models.User{})

	if result.Error != nil && result.Error.Error() == `record not found` {
		log.Info("User does not exist")
		errString := "user does not exist"
		return 404, errors.New(errString)
	}

	// hash the newPassword string

	hashedPassword, err := helper.HashPassword(newPassword)

	if err != nil {
		log.Error("Error hashing password")
		return 500, err
	}

	// update the password field of the user in the database

	// check if the user is present in the database

	result = a.DB.Conn.Table("users").Where("email = ?", user.Email).Update("password", string(hashedPassword))

	if result.Error != nil {
		log.Error("Error updating password")
		return 500, result.Error
	}

	log.Info("Password reset successfully")
	return 200, nil
}
