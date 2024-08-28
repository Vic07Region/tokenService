package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"tokenService/internal/database"
	"tokenService/internal/handles"
)

var (
	sercret_key = "sdasdasdsadasde422323"
)

func main() {
	db, err := database.New("user=postgres dbname=tknserv password=12345678 sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	storage := database.NewService(db, sercret_key)
	router := handles.New(ctx, storage)
	http.HandleFunc("/users/token", router.GetToken)
	http.HandleFunc("/users/refresh", router.RefreshToken)
	fmt.Println("Сервер запущен на порту 8080")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}
