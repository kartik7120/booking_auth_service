package auth

import (
	"database/sql"
	"encoding/base64"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	a "github.com/kartik7120/booking_auth_service/cmd/auth"
	"github.com/kartik7120/booking_auth_service/cmd/helper"
)

type DBMock struct {
	Conn *sql.DB
}

func NewDBMock() *DBMock {
	return &DBMock{}
}

func (d *DBMock) InsertDB(queryString string) error {
	return nil
}

func (d *DBMock) UpdateDB(queryString string) error {
	return nil
}

func (d *DBMock) DeleteDB(queryString string) error {
	return nil
}

func (d *DBMock) SelectDB(queryString string) (*sql.Rows, error) {
	return nil, nil
}

func TestRegisterAuth(t *testing.T) {
	t.Run("Test to register a user using default fields", func(t *testing.T) {
		// Create a new authentication instance
		authInstance := a.NewAuthentication(10)

		// Create a new user
		user := a.User{
			Username: "",
			Email:    "",
			Password: "",
		}

		// Register the user
		_, err := authInstance.Register(user)

		if err == nil {
			t.Errorf("Should throw error when create a user with empty fields: %v", err)
		}
	})

	t.Run("Test to register a user that does not exist using valid fields", func(t *testing.T) {
		// Create a new authentication instance
		db, mock, err := sqlmock.New()

		if err != nil {
			t.Errorf("Error creating a new mock database connection: %v", err)
			return
		}

		authInstance := a.NewAuthentication(10)

		d := NewDBMock()
		d.Conn = db

		authInstance.DB = &helper.DBConfig{
			Conn: d.Conn,
		}

		// Create a new user
		user := a.User{
			Username: "kartik7120",
			Email:    "kaartikshukla7120@gmail.com",
			Password: "password",
		}

		// Register the user
		mock.ExpectQuery("^SELECT \\* FROM users WHERE username = \\?$").WithArgs(user.Username).WillReturnRows(sqlmock.NewRows(nil))

		token, err := authInstance.Register(user)

		if err != nil {
			t.Errorf("Should not throw error when create a user with valid fields: %v", err)
			return
		}

		// Parse token and check if the token is valid with a uid field set to username
		fn := func(token *jwt.Token) (interface{}, error) {
			keyBase64 := os.Getenv("JWT_KEY_BASE64")
			keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
			if err != nil {
				return nil, err
			}
			return keyBytes, nil
		}

		if token == "" {
			t.Errorf("Token should not be empty after registering a user: %v", token)
		}

		_, err = jwt.Parse(token, fn, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("auth-service"), jwt.WithExpirationRequired())

		if err != nil {
			t.Errorf("Should not throw error when parse a valid token: %v", err)
		}
	})

	t.Run("Test to register a user that already exists", func(t *testing.T) {
		// Create a new authentication instance
		db, mock, err := sqlmock.New()

		if err != nil {
			t.Errorf("Error creating a new mock database connection: %v", err)
			return
		}

		authInstance := a.NewAuthentication(10)

		d := NewDBMock()
		d.Conn = db

		authInstance.DB = &helper.DBConfig{
			Conn: d.Conn,
		}

		// Create a new user
		user := a.User{
			Username: "kartik7120",
			Email:    "kaartikshukla7120@gmail.com",
			Password: "password",
		}

		mock.ExpectQuery("^SELECT \\* FROM users WHERE username = \\?$").WithArgs(user.Username).WillReturnRows(sqlmock.NewRows([]string{"username"}).AddRow(user.Username))

		// Register the user

		_, err = authInstance.Register(user)

		if err == nil {
			t.Errorf("Should throw error when create a user with a username that already exists: %v", err)
		}

		if err.Error() != "user with the same username already exists" {
			t.Errorf("Should throw error with message 'user with the same username already exists': %v", err)
		}
	})

	t.Run("Test to save a user with a hashed password", func(t *testing.T) {
		// Create a new authentication instance
		db, _, err := sqlmock.New()

		if err != nil {
			t.Errorf("Error creating a new mock database connection: %v", err)
			return
		}

		authInstance := a.NewAuthentication(10)

		d := NewDBMock()
		d.Conn = db

		authInstance.DB = &helper.DBConfig{
			Conn: d.Conn,
		}

		// Create a new user
		// user := a.User{
		// 	Username: "kartik7120",
		// 	Email:    "kaartikshukla7120@gmail.com",
		// 	Password: "password",
		// }

	})
}

func TestLoginAuth(t *testing.T) {
	t.Run("Test to login a user using default fields", func(t *testing.T) {
		db, _, err := sqlmock.New()

		if err != nil {
			t.Errorf("Error creating a new mock database connection: %v", err)
			return
		}

		authInstance := a.NewAuthentication(10)

		d := NewDBMock()
		d.Conn = db

		authInstance.DB = &helper.DBConfig{
			Conn: d.Conn,
		}

		// Create a new user with default values

		user := a.LoginUser{
			Username: "",
			Password: "",
		}

		// Login the user

		_, err = authInstance.Login(user)

		if err == nil {
			t.Errorf("Should throw error when login a user with empty fields: %v", err)
		}

	})

	t.Run("Test to login a user using valid fields", func(t *testing.T) {
		db, _, err := sqlmock.New()

		if err != nil {
			t.Errorf("Error creating a new mock database connection: %v", err)
			return
		}

		authInstance := a.NewAuthentication(10)

		d := NewDBMock()
		d.Conn = db

		authInstance.DB = &helper.DBConfig{
			Conn: d.Conn,
		}
	})

	t.Run("Test to login a user that does not exist", func(t *testing.T) {
		db, mock, err := sqlmock.New()

		if err != nil {
			t.Errorf("Error creating a new mock database connection: %v", err)
			return
		}

		authInstance := a.NewAuthentication(10)

		d := NewDBMock()
		d.Conn = db

		authInstance.DB = &helper.DBConfig{
			Conn: d.Conn,
		}

		// Create a new user

		user := a.LoginUser{
			Username: "kartik7120",
			Password: "password",
		}

		mock.ExpectQuery("^SELECT \\* FROM users WHERE username = \\?$").WithArgs(user.Username).WillReturnRows(sqlmock.NewRows(nil))

		// Login the user

		_, err = authInstance.Login(user)

		if err == nil {
			t.Errorf("Should throw error when login a user that does not exist: %v", err)
		}

		if err.Error() != "user does not exist" {
			t.Errorf("Should throw error with message 'user does not exist': %v", err)
		}
	})

	t.Run("Test to login a user with invalid password", func(t *testing.T) {
		db, mock, err := sqlmock.New()

		if err != nil {
			t.Errorf("Error creating a new mock database connection: %v", err)
			return
		}

		authInstance := a.NewAuthentication(10)

		d := NewDBMock()
		d.Conn = db

		authInstance.DB = &helper.DBConfig{
			Conn: d.Conn,
		}

		// Create a new user

		user := a.LoginUser{
			Username: "kartik7120",
			Password: "passwo",
		}

		// A existing user will also have a hashed password
		mock.ExpectQuery("^SELECT \\* FROM users WHERE username = \\?$").WithArgs(user.Username).WillReturnRows(sqlmock.NewRows([]string{"password"}).AddRow("password"))

		// Login the user

		_, err = authInstance.Login(user)

		if err == nil {
			t.Errorf("Should throw error when login a user with invalid password: %v", err)
		}

		if err.Error() != "invalid password" {
			t.Errorf("Should throw error with message 'invalid password': %v", err)
		}

	})
}
