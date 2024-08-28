// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package queries

import (
	"database/sql"

	"github.com/google/uuid"
)

type Token struct {
	TokenID          int64          `json:"token_id"`
	UserID           uuid.NullUUID  `json:"user_id"`
	RefreshTokenHash string         `json:"refresh_token_hash"`
	IpAddressIssue   sql.NullString `json:"ip_address_issue"`
	Refreshed        bool           `json:"refreshed"`
}

type User struct {
	UserID       uuid.UUID      `json:"user_id"`
	Username     string         `json:"username"`
	PasswordHash string         `json:"password_hash"`
	Email        string         `json:"email"`
	IpAddress    sql.NullString `json:"ip_address"`
}
