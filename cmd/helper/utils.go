package helper

import "math/rand"

func GenerateRandomNumberString(length int) string {
	// rand.Seed(time.Now().UnixNano())
	numbers := "0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = numbers[rand.Intn(len(numbers))]
	}
	return string(result)
}
