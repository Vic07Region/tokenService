package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"time"
	"tokenService/internal/database/queries"
	jwt_layer "tokenService/internal/jwt"
)

type Token struct {
	Access  string
	Refresh string
	TokenID int64
}

type TokenParams struct {
	GUID    string
	User_ip string
}

func (s *Service) CreateToken(ctx context.Context, params *TokenParams) (*Token, error) {
	userGuid, err := uuid.Parse(params.GUID)
	if err != nil {
		return nil, fmt.Errorf("UUID Parsing error: %s", err)
	}

	refresh_token, err := s.Jwt.GenerateToken(&jwt_layer.TokenParams{
		GUID:       params.GUID,
		TokenType:  "Refresh",
		TokenID:    0,
		Expiration: 10 * (24 * time.Hour),
	})

	if err != nil {
		return nil, fmt.Errorf("Generate Refresh error:", err)
	}
	hash := sha256.Sum256([]byte(refresh_token))
	hash_token := hex.EncodeToString(hash[:])
	//hash_token, err := bcrypt.GenerateFromPassword([]byte(refresh_token), bcrypt.DefaultCost)
	//if err != nil {
	//	return nil, fmt.Errorf("Hashed error: %s", err)
	//}
	s.mu.Lock()
	token_id, err := s.queries.CreateToken(ctx, queries.CreateTokenParams{
		UserID: uuid.NullUUID{
			UUID:  userGuid,
			Valid: true,
		},
		RefreshTokenHash: string(hash_token),
		IpAddressIssue: sql.NullString{
			String: params.User_ip,
			Valid:  true,
		},
	})
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("Create token error: %s", err)
	}

	access_token, err := s.Jwt.GenerateToken(&jwt_layer.TokenParams{
		GUID:       params.GUID,
		TokenType:  "Access",
		TokenID:    token_id,
		Expiration: 24 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("Generate Access error:", err)
	}
	return &Token{
		Access:  access_token,
		Refresh: refresh_token,
		TokenID: token_id,
	}, nil
}

type UserTokenResp struct {
	TokenID          int64     `json:"token_id"`
	UserID           uuid.UUID `json:"user_id"`
	RefreshTokenHash string    `json:"refresh_token_hash"`
	UserIp           string    `json:"user_ip"`
	Refreshed        bool      `json:"refreshed"`
}

func (s *Service) FetchToken(ctx context.Context, refresh_token string) (*UserTokenResp, error) {
	hash := sha256.Sum256([]byte(refresh_token))
	hash_token := hex.EncodeToString(hash[:])
	tkn, err := s.queries.FetchToken(ctx, hash_token)
	if err != nil {
		return nil, fmt.Errorf("Fetchin user error: %s", err)
	}

	return &UserTokenResp{
		TokenID:          tkn.TokenID,
		UserID:           tkn.UserID.UUID,
		RefreshTokenHash: tkn.RefreshTokenHash,
		UserIp:           tkn.IpAddressIssue.String,
		Refreshed:        tkn.Refreshed,
	}, nil

}

func (s *Service) TokenRefreshed(ctx context.Context, token_id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries.RefreshedToken(ctx, token_id)
}
