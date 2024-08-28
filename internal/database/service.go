package database

import (
	"database/sql"
	"sync"
	"tokenService/internal/database/queries"
	jwt_layer "tokenService/internal/jwt"
)

type Service struct {
	queries *queries.Queries
	db      *sql.DB
	mu      sync.Mutex
	Jwt     *jwt_layer.JwtToken
}

func NewService(db *sql.DB, secret_key string) *Service {
	return &Service{
		db:      db,
		queries: queries.New(db),
		Jwt:     jwt_layer.New(secret_key),
	}
}
