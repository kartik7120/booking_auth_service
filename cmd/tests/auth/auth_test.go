package auth

import (
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	a "github.com/kartik7120/booking_auth_service/cmd/auth"
)

func TestAuth(t *testing.T) {
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

	t.Run("Test to register a user using valid fields", func(t *testing.T) {

		// Create a new authentication instance

		authInstance := a.NewAuthentication(10)

		// Create a new user

		user := a.User{
			Username: "kartik7120",
			Email:    "kaartikshukla7120@gmail.com",
			Password: "password",
		}

		// Register the user

		token, err := authInstance.Register(user)

		if err != nil {
			t.Errorf("Should not throw error when create a user with valid fields: %v", err)
			return
		}

		// Parse token and check if the token is valid with a uid field set to username
		fn := func(token *jwt.Token) (interface{}, error) {
			secret := os.Getenv("JWT_KEY")
			return []byte(secret), nil
		}

		if token == "" {
			t.Errorf("Token should not be empty after registering a user: %v", token)
		}

		_, err = jwt.Parse(token, fn, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer("auth-service"), jwt.WithExpirationRequired())

		if err != nil {
			t.Errorf("Should not throw error when parse a valid token: %v", err)
		}
	})

}
