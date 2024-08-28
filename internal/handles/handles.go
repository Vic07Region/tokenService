package handles

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
	"tokenService/internal/database"
)

var (
	InvalidParams    = "Некорректные параметры запроса"
	MethodNotAllowed = "Метод не разрешен"
	IpParseError     = "Не удалось определить IP-адрес"
)

type Routes struct {
	dbq *database.Service
	ctx context.Context
	mu  sync.Mutex
}

func New(ctx context.Context, dbq *database.Service) *Routes {
	return &Routes{
		dbq: dbq,
		ctx: ctx,
	}
}

type GetTokenParams struct {
	GUID string `json:"guid"`
}

func (rts *Routes) GetToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, MethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	user_ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, IpParseError, http.StatusInternalServerError)
		return
	}
	var user_id GetTokenParams

	err = json.NewDecoder(r.Body).Decode(&user_id)
	if err != nil {
		http.Error(w, InvalidParams, http.StatusBadRequest)
		return
	}
	_, err = rts.dbq.FetchUser(rts.ctx, user_id.GUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokens, err := rts.dbq.CreateToken(rts.ctx, &database.TokenParams{
		GUID:    user_id.GUID,
		User_ip: user_ip,
	})
	if err != nil {
		fmt.Println("Error Create Token:", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"access_token":  tokens.Access,
		"refresh_token": tokens.Refresh,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(response)
}

type RefreshTokenParams struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (rts *Routes) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, MethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	user_ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, IpParseError, http.StatusInternalServerError)
		return
	}
	var tokens RefreshTokenParams
	err = json.NewDecoder(r.Body).Decode(&tokens)
	if err != nil {
		http.Error(w, InvalidParams, http.StatusBadRequest)
		return
	}

	refresh_claims, err := rts.dbq.Jwt.ParseToken(tokens.RefreshToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	access_claims, err := rts.dbq.Jwt.ParseToken(tokens.AccessToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	if refresh_claims.ExpiresAt <= time.Now().Unix() {
		http.Error(w, "Refresh token has expired", http.StatusUnauthorized)
	}
	rts.mu.Lock()
	defer rts.mu.Unlock()
	db_token, err := rts.dbq.FetchToken(rts.ctx, tokens.RefreshToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if db_token.Refreshed {
		http.Error(w, "The token has already been updated", http.StatusUnauthorized)
		return
	}

	if access_claims.TokenID != db_token.TokenID {
		http.Error(w, "Refresh Token does not use to Access Token", http.StatusUnauthorized)
		return
	}

	newTokens, err := rts.dbq.CreateToken(rts.ctx, &database.TokenParams{
		GUID:    db_token.UserID.String(),
		User_ip: user_ip,
	})
	if err != nil {
		http.Error(w, "Create Tokens error:"+err.Error(), http.StatusInternalServerError)
		return
	}

	err = rts.dbq.TokenRefreshed(rts.ctx, db_token.TokenID)
	if err != nil {
		http.Error(w, "Refresh Token error:"+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"access_token":  newTokens.Access,
		"refresh_token": newTokens.Refresh,
	}

	if db_token.UserIp != user_ip {
		user, err := rts.dbq.FetchUser(rts.ctx, db_token.UserID.String())
		if err != nil {
			fmt.Println("Send mail to user error:", err)
		}
		fmt.Printf("Send to:%s warning message", user.Email)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(response)
}
