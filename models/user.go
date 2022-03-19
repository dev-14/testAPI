package models

import "time"

type UserRole struct {
	Id   int    `json:"id,string"`
	Role string `json:"role"`
}

type User struct {
	ID         int    `json:"id" gorm:"autoIncrement"`
	FirstName  string `json:"firstname"`
	LastName   string `json:"lastname"`
	Email      string `json:"email" gorm:"unique"`
	Mobile     string `json:"mobile" gorm:"unique"`
	UserRoleID int    `json:"role_id,string"`
	Password   string `json:"-"`

	CreatedAt time.Time `json:"created_at,timestamp"`
	UpdatedAt time.Time `json:"updated_at,timestamp"`
	IsActive  bool      `json:"is_active,boolean"`
}
