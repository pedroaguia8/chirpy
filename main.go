package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/pedroaguia8/chirpy/internal/database"
	"github.com/pedroaguia8/chirpy/internal/handlers"
)
import _ "github.com/lib/pq"

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Couldn't load environment variables from .env file")
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)
	apiConfig := handlers.ApiConfig{}
	apiConfig.Db = dbQueries
	apiConfig.Platform = os.Getenv("PLATFORM")

	mux := http.NewServeMux()

	// TODO: create specific folder for served files
	handler := http.StripPrefix("/app/", http.FileServer(http.Dir("app")))
	mux.Handle("/app/", apiConfig.MiddlewareMetricsInc(handler))
	mux.Handle("GET /api/healthz", apiConfig.MiddlewareMetricsInc(http.HandlerFunc(handlers.Readiness)))
	mux.Handle("POST /admin/reset", http.HandlerFunc(apiConfig.Reset))
	mux.Handle("GET /admin/metrics", http.HandlerFunc(apiConfig.Metrics))
	mux.Handle("POST /api/chirps", http.HandlerFunc(apiConfig.CreateChirp))
	mux.Handle("GET /api/chirps", http.HandlerFunc(apiConfig.GetChirps))
	mux.Handle("GET /api/chirps/{chirpId}", http.HandlerFunc(apiConfig.GetChirp))
	mux.Handle("POST /api/users", http.HandlerFunc(apiConfig.CreateUser))

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
