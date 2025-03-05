// filepath: /home/kartik7120/booking_auth_service/cmd/tests/mail/mail_test.go
package mail

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMail(t *testing.T) {
	t.Run("Send mail to a email address", func(t *testing.T) {

		url := "https://send.api.mailtrap.io/api/send"
		method := "POST"

		payload := strings.NewReader(`{
            "from": {
                "email": "hello@demomailtrap.co",
                "name": "Mailtrap Test"
            },
            "to": [
                {
                    "email": "kaartikshukla7120@gmail.com"
                }
            ],
            "subject": "You are awesome!",
            "text": "Congrats for sending test email with Mailtrap!",
            "category": "Integration Test"
        }`)

		client := &http.Client{}
		req, err := http.NewRequest(method, url, payload)

		if err != nil {
			fmt.Println(err)
			return
		}
		req.Header.Add("Authorization", "Bearer 20a403cfe90b0e710efaf014d32fc561")
		req.Header.Add("Content-Type", "application/json")

		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(string(body))

	})
}
