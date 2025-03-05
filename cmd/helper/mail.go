package helper

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

// If this mail implementation is not working for us then we can also host mailhog on our local machine

func SendMail(to string, name string, text string, html string, category string, subject string) error {

	// validating if the email is valid

	err := validate.Var(to, "email")

	if err != nil {
		return err
	}

	if len(text) == 0 && len(html) == 0 {
		return fmt.Errorf("text or html is required")
	}

	// check if text or html does not contain any malicious code

	if len(text) > 0 {
		err = validate.Var(text, "printascii")

		if err != nil {
			return err
		}
	}

	if len(html) > 0 {

		err = validate.Var(html, "printascii")

		if err != nil {
			return err
		}

		err = validate.Var(html, "html")

		if err != nil {
			return err
		}

	}

	if len(subject) > 0 {
		err = validate.Var(subject, "printascii")

		if err != nil {
			return err
		}
	}

	url := "https://send.api.mailtrap.io/api/send"
	method := "POST"

	payloadString := ""

	if len(html) > 0 {
		payloadString = fmt.Sprintf(`{
			"from": {
				"email": "hello@demomailtrap.co",
				"name": %s
			},
			"to": [
				{
					"email": %s
				}
			],
			"subject": %s,
			"html": %s,
			"category": %s
		}`, name, to, subject, html, category)
	} else {
		payloadString = fmt.Sprintf(`{
				"from": {
					"email": "hello@demomailtrap.co",
					"name": %s
				},
				"to": [
					{
						"email": %s
					}
				],
				"subject": %s,
				"text": %s,
				"category": %s
			}`, name, to, subject, text, category)
	}

	payload := strings.NewReader(payloadString)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return err
	}

	req.Header.Add("Authorization", "Bearer 3deb1327c08f477ca4d57b450f0e4161")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)

	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println(string(body))

	return nil
}
