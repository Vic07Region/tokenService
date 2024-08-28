package jwt_layer

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"time"
)

type JwtToken struct {
	secret_key string
}

func New(secret_key string) *JwtToken {
	return &JwtToken{secret_key: secret_key}
}

type Claims struct {
	GUID      string `json:"guid"`
	TokenType string `json:"token_type"`
	TokenID   int64  `json:"token_id"`
	*jwt.StandardClaims
}

type TokenParams struct {
	GUID       string
	TokenType  string
	TokenID    int64
	Expiration time.Duration
}

func (t *JwtToken) GenerateToken(params *TokenParams) (string, error) {
	jwt_claim := Claims{
		GUID:      params.GUID,
		TokenType: params.TokenType,
		TokenID:   params.TokenID,
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(params.Expiration).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt_claim)
	tokenString, err := token.SignedString([]byte(t.secret_key))
	if err != nil {
		return "", fmt.Errorf("signed Error: %s", err)
	}
	return tokenString, nil
}

func (t *JwtToken) ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS512 {
			return nil, fmt.Errorf("Signing method Invalid")
		}
		if token.Claims.(*Claims).TokenType != "Refresh" && token.Claims.(*Claims).TokenType != "Access" {
			return nil, fmt.Errorf("Token not Valid")
		}
		return []byte(t.secret_key), nil

	})
	if err != nil {
		return nil, err
	}

	return token.Claims.(*Claims), nil

}
