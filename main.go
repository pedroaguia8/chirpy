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
	if err != nil {
		log.Fatalf("Couldn't connect to database: %v", err)
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Fatalf("Couldn't close database: %v", err)
		}
	}(db)

	dbQueries := database.New(db)
	apiConfig := handlers.ApiConfig{}
	apiConfig.Db = dbQueries
	apiConfig.Platform = os.Getenv("PLATFORM")
	apiConfig.JwtSecret = os.Getenv("JWT_SECRET")
	apiConfig.PolkaKey = os.Getenv("POLKA_KEY")

	mux := http.NewServeMux()

	// TODO: create specific folder for served files
	handler := http.StripPrefix("/app/", http.FileServer(http.Dir("app")))
	mux.Handle("/app/", apiConfig.MiddlewareMetricsInc(handler))
	mux.Handle("GET /api/healthz", apiConfig.MiddlewareMetricsInc(http.HandlerFunc(handlers.Readiness)))
	mux.Handle("POST /admin/reset", http.HandlerFunc(apiConfig.Reset))
	mux.Handle("GET /admin/metrics", http.HandlerFunc(apiConfig.Metrics))
	mux.Handle("POST /api/users", http.HandlerFunc(apiConfig.CreateUser))
	mux.Handle("POST /api/login", http.HandlerFunc(apiConfig.Login))
	mux.Handle("POST /api/chirps", http.HandlerFunc(apiConfig.CreateChirp))
	mux.Handle("GET /api/chirps", http.HandlerFunc(apiConfig.GetChirps))
	mux.Handle("GET /api/chirps/{chirpId}", http.HandlerFunc(apiConfig.GetChirp))
	mux.Handle("POST /api/refresh", http.HandlerFunc(apiConfig.RefreshToken))
	mux.Handle("POST /api/revoke", http.HandlerFunc(apiConfig.RevokeRefreshToken))
	mux.Handle("PUT /api/users", http.HandlerFunc(apiConfig.UpdateUserEmailPassword))
	mux.Handle("DELETE /api/chirps/{chirpId}", http.HandlerFunc(apiConfig.DeleteChirp))
	mux.Handle("POST /api/polka/webhooks", http.HandlerFunc(apiConfig.UpgradeUser))

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
