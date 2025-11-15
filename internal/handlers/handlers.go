package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pedroaguia8/chirpy/internal/auth"
	"github.com/pedroaguia8/chirpy/internal/database"
	"github.com/pedroaguia8/chirpy/internal/utils"
)

type ApiConfig struct {
	fileserverHits atomic.Int32
	Db             *database.Queries
	Platform       string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
}

func databaseUserToUser(dbUser database.User) User {
	return User{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		PasswordHash: dbUser.HashedPassword,
	}
}

func (cfg *ApiConfig) CreateUser(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
	if strings.TrimSpace(params.Email) == "" {
		err := utils.RespondWithError(w, http.StatusBadRequest, "Email cannot be empty")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
	if strings.TrimSpace(params.Password) == "" {
		err := utils.RespondWithError(w, http.StatusBadRequest, "Password cannot be empty")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	passwordHash, err := auth.HashPassword(params.Password)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to hash password")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	dbUser, err := cfg.Db.CreateUser(req.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: passwordHash,
	})
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create user")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
	user := databaseUserToUser(dbUser)
	err = utils.RespondWithJSON(w, http.StatusCreated, user)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create user")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
}

func (cfg *ApiConfig) Login(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Couldn't decode input")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	dbUser, err := cfg.Db.GetUserByEmail(req.Context(), params.Email)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusBadRequest, "Failed to login")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
	user := databaseUserToUser(dbUser)

	match, err := auth.CheckPasswordHash(params.Password, user.PasswordHash)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to login")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	if !match {
		err := utils.RespondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	err = utils.RespondWithJSON(w, http.StatusOK, user)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to login")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
}

func databaseChirpToChirp(dbChirp database.Chirp) Chirp {
	return Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserId:    dbChirp.UserID,
	}
}

func (cfg *ApiConfig) CreateChirp(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Body   string    `json:"body"`
		UserId uuid.UUID `json:"user_id"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "couldn't decode parameters")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	if validationErr := validateChirp(params.Body); validationErr != nil {
		err := utils.RespondWithError(w, http.StatusBadRequest, validationErr.Error())
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	cleanedBody := utils.FilterProfanity(params.Body)

	dbChirp, err := cfg.Db.CreateChirp(req.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: params.UserId,
	})
	if err != nil {
		// TODO: distinguish between different errs with help of db driver (do a switch case)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Failed to post chirp")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
	chirp := databaseChirpToChirp(dbChirp)

	err = utils.RespondWithJSON(w, http.StatusCreated, chirp)
	if err != nil {
		log.Printf("Failed to respond with json payload: %v", err)
	}
}

func validateChirp(chirp string) error {
	if utf8.RuneCountInString(chirp) > 140 {
		return errors.New("Chirp is too long")
	}
	if strings.TrimSpace(chirp) == "" {
		return errors.New("Chirp body cannot be empty")
	}
	return nil
}

func (cfg *ApiConfig) GetChirps(w http.ResponseWriter, req *http.Request) {
	dbChirps, err := cfg.Db.GetChirps(req.Context())
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get chirps")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, databaseChirpToChirp(dbChirp))
	}

	err = utils.RespondWithJSON(w, http.StatusOK, chirps)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get chirps")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
}

func (cfg *ApiConfig) GetChirp(w http.ResponseWriter, req *http.Request) {
	chirpIdStr := req.PathValue("chirpId")
	chirpId, err := uuid.Parse(chirpIdStr)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusBadRequest, "Invalid chirp id")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	dbChirp, err := cfg.Db.GetChirp(req.Context(), chirpId)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusNotFound, "Failed to find chirp")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	chirp := databaseChirpToChirp(dbChirp)
	err = utils.RespondWithJSON(w, http.StatusOK, chirp)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get chirp")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
}

func (cfg *ApiConfig) Reset(w http.ResponseWriter, req *http.Request) {
	if cfg.Platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	cfg.fileserverHits.Store(0)

	err := cfg.Db.DeleteUsers(req.Context())
	if err != nil {
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to delete users")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

func Readiness(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	_, err := w.Write([]byte("OK"))
	if err != nil {
		log.Println("error writing response body: %w", err)
	}
}
