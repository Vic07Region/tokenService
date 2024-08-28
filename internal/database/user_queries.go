package database

import (
	"context"
	"fmt"
	"github.com/google/uuid"
)

type User struct {
	UserID       uuid.UUID `json:"user_id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Email        string    `json:"email"`
	IpAddress    string    `json:"ip_address"`
}

func (s *Service) FetchUser(ctx context.Context, userid string) (*User, error) {
	guid, err := uuid.Parse(userid)
	if err != nil {
		return nil, fmt.Errorf("UUID Parsing error:", err)

	}

	if guid.Version().String() != "VERSION_4" {
		return nil, fmt.Errorf("Wrong UUID")
	}

	user, err := s.queries.FetchUser(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("Fetchin user error:", err)
	}
	return &User{
		UserID:       user.UserID,
		Username:     user.Username,
		PasswordHash: user.PasswordHash,
		Email:        user.Email,
		IpAddress:    user.IpAddress.String,
	}, nil
}
