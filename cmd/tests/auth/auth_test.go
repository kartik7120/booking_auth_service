package auth

import (
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/kartik7120/booking_auth_service/cmd/auth"
	"github.com/kartik7120/booking_auth_service/cmd/models"
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

func TestAuth(t *testing.T) {
	t.Run("Testing if register function is running properly", func(t *testing.T) {
		// Create a new authentication instance
		authInstance := auth.NewAuthentication(10)

		// Create a new user
		user := models.User{
			Username: "Naomi Green",
			Email:    "Emerald34@hotmail.com",
			Password: "XgvnSXkx1t5gsCe",
		}

		// Register the user
		_, _, err := authInstance.Register(user)

		if err == nil {
			t.Errorf("Should throw error when create a user with empty fields: %v", err)
		}
	})

	t.Run("Migrate the database", func(t *testing.T) {
		// Create a new authentication instance
		db := auth.NewAuthentication(10)

		db.DB.Conn.AutoMigrate(&models.User{})
	})
}
