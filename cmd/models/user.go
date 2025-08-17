package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	// Username string `json:"username" validate:"required,alphanum" gorm:"unique"`
	Email    string `json:"email" validate:"required,email" gorm:"unique"`
	Password string `json:"password" validate:"required,alphanum"`
	Role     string `json:"role" gorm:"default:USER"`
}

type LoginUser struct {
	// Username string `json:"username" validate:"required,alphanum"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,alphanum"`
}
