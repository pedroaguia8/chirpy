package handlers

import (
	"database/sql"
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
	JwtSecret      string
	PolkaKey       string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsUpgraded   bool      `json:"is_upgraded"`
}

func databaseUserToUser(dbUser database.User) User {
	return User{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		PasswordHash: dbUser.HashedPassword,
		IsUpgraded:   dbUser.IsUpgraded,
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
		log.Printf("ERROR: Couldn't decode parameters: %v", err)
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
		log.Printf("ERROR: Failed to hash password: %v", err)
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
		log.Printf("ERROR: Failed to create user in database: %v", err)
		respErr := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create user")
		if respErr != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}
	user := databaseUserToUser(dbUser)
	err = utils.RespondWithJSON(w, http.StatusCreated, user)
	if err != nil {
		log.Printf("ERROR: Failed to write JSON response: %v", err)
	}
}

func (cfg *ApiConfig) UpdateUserEmailPassword(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("ERROR: Couldn't decode parameters: %v", err)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Couldn't decode parameters")
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
		log.Printf("ERROR: Failed to hash password: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to hash password")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("ERROR: Failed to get access token from header: %v", err)
		err := utils.RespondWithError(w, http.StatusUnauthorized, "Bad request: failed to find access token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	userId, err := auth.ValidateJWT(token, cfg.JwtSecret)
	if err != nil {
		log.Printf("ERROR: Failed to validate jwt token: %v", err)
		err := utils.RespondWithError(w, http.StatusUnauthorized, "Bad request: bad access token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	dbUser, err := cfg.Db.UpdateUserEmailPassword(req.Context(), database.UpdateUserEmailPasswordParams{
		Email:          params.Email,
		HashedPassword: passwordHash,
		ID:             userId,
	})
	if err != nil {
		log.Printf("ERROR: Failed to update user's email and password: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update user")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	type response struct {
		ID         uuid.UUID `json:"id"`
		CreatedAt  time.Time `json:"created_at"`
		UpdatedAt  time.Time `json:"updated_at"`
		Email      string    `json:"email"`
		IsUpgraded bool      `json:"is_upgraded"`
	}
	res := response{
		ID:         dbUser.ID,
		CreatedAt:  dbUser.CreatedAt,
		UpdatedAt:  dbUser.UpdatedAt,
		Email:      dbUser.Email,
		IsUpgraded: dbUser.IsUpgraded,
	}

	err = utils.RespondWithJSON(w, http.StatusOK, res)
	if err != nil {
		log.Printf("Failed to send response to client: %v", err)
		return
	}
}

func (cfg *ApiConfig) UpgradeUser(w http.ResponseWriter, req *http.Request) {
	polkaKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		log.Printf("ERROR: Couldn't parse polka api key: %v", err)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Couldn't parse API key")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	if polkaKey != cfg.PolkaKey {
		log.Printf("ERROR: Incorrect Polka API key: %v", err)
		err := utils.RespondWithError(w, http.StatusUnauthorized, "Incorrect API key")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserId string `json:"user_id"`
		} `json:"data"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("ERROR: Couldn't decode request parameters: %v", err)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Couldn't decode input")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	if params.Event != "user.upgraded" {
		log.Printf("ERROR: Webhook event not recognized: %v", err)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Failed to upgrade user")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	userId, err := uuid.Parse(params.Data.UserId)
	if err != nil {
		log.Printf("ERROR: Failed to parse uuid: %v", err)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Failed to parse user id")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	_, err = cfg.Db.UpgradeUser(req.Context(), userId)
	if err != nil {
		log.Printf("ERROR: Failed to upgrade user in database: %v", err)
		err := utils.RespondWithError(w, http.StatusNotFound, "User not found")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
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
		log.Printf("ERROR: Couldn't decode login parameters: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Couldn't decode input")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	expiresIn, err := time.ParseDuration("1h")
	if err != nil {
		log.Printf("ERROR: Couldn't token expiration duration: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to login")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	dbUser, err := cfg.Db.GetUserByEmail(req.Context(), params.Email)
	if err != nil {
		log.Printf("ERROR: Failed to get user by email %s: %v", params.Email, err)
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
		log.Printf("ERROR: Failed to check password hash: %v", err)
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

	token, err := auth.MakeJWT(user.ID, cfg.JwtSecret, expiresIn)
	if err != nil {
		log.Printf("ERROR: Failed to create JWT: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to login")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	user.Token = token

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("ERROR: Failed to make refresh token: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to login")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	savedRefreshToken, err := cfg.Db.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
		Token:  refreshToken,
		UserID: user.ID,
		ExpiresAt: sql.NullTime{
			Time:  time.Now().AddDate(0, 0, 60),
			Valid: true,
		},
	})
	if err != nil {
		log.Printf("ERROR: Failed to save refresh token: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to login")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	user.RefreshToken = savedRefreshToken.Token

	err = utils.RespondWithJSON(w, http.StatusOK, user)
	if err != nil {
		log.Printf("ERROR: Failed to write JSON response: %v", err)
	}
}

func (cfg *ApiConfig) RefreshToken(w http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("ERROR: Failed to get bearer token from header: %v", err)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Bad request: failed to find refresh token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	dbRefreshToken, err := cfg.Db.GetRefreshToken(req.Context(), refreshToken)
	if err != nil {
		log.Printf("ERROR: Failed to get refresh token from database: %v", err)
		err := utils.RespondWithError(w, http.StatusUnauthorized, "Failed to refresh token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	if dbRefreshToken.ExpiresAt.Time.Before(time.Now()) || dbRefreshToken.RevokedAt.Valid == true {
		err := utils.RespondWithError(w, http.StatusUnauthorized, "Failed to refresh token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	dbUser, err := cfg.Db.GetUserFromRefreshToken(req.Context(), refreshToken)
	if err != nil {
		log.Printf("ERROR: Failed to get user from database: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to refresh token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	token, err := auth.MakeJWT(dbUser.ID, cfg.JwtSecret, time.Hour)
	if err != nil {
		log.Printf("ERROR: Failed to make jwt token: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to refresh token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	type response struct {
		Token string `json:"token"`
	}

	err = utils.RespondWithJSON(w, http.StatusOK, response{Token: token})
	if err != nil {
		log.Printf("ERROR: Failed to write JSON response: %v", err)
	}
}

func (cfg *ApiConfig) RevokeRefreshToken(w http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("ERROR: Failed to get bearer token from header: %v", err)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Bad request: failed to find refresh token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	dbRefreshToken, err := cfg.Db.GetRefreshToken(req.Context(), refreshToken)
	if err != nil {
		log.Printf("ERROR: Failed to get refresh token from database: %v", err)
		err := utils.RespondWithError(w, http.StatusUnauthorized, "Failed to revoke token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	if dbRefreshToken.ExpiresAt.Time.Before(time.Now()) || dbRefreshToken.RevokedAt.Valid == true {
		err := utils.RespondWithError(w, http.StatusUnauthorized, "Failed to revoke token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	err = cfg.Db.RevokeRefreshToken(req.Context(), refreshToken)
	if err != nil {
		log.Printf("ERROR: Failed to get revoke refresh token in database: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to revoke token")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
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
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("ERROR: Couldn't decode chirp parameters: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "couldn't decode parameters")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusBadRequest, "Bad authorization header")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	userId, err := auth.ValidateJWT(token, cfg.JwtSecret)
	if err != nil {
		err := utils.RespondWithError(w, http.StatusUnauthorized, "Failed to validate user")
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
		UserID: userId,
	})
	if err != nil {
		log.Printf("ERROR: Failed to create chirp in database: %v", err)
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
		log.Printf("ERROR: Failed to write JSON response: %v", err)
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
	authorIdStr := req.URL.Query().Get("author_id")

	dbChirps := []database.Chirp{}
	var err error

	if authorIdStr == "" {
		dbChirps, err = cfg.Db.GetChirps(req.Context())
		if err != nil {
			log.Printf("ERROR: Failed to get chirps from database: %v", err)
			err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get chirps")
			if err != nil {
				log.Printf("Failed to send error response to client: %v", err)
				return
			}
			return
		}
	} else {
		authorId, err := uuid.Parse(authorIdStr)
		if err != nil {
			log.Printf("ERROR: Failed to parse author id to UUID: %v", err)
			err := utils.RespondWithError(w, http.StatusBadRequest, "Bad author id")
			if err != nil {
				log.Printf("Failed to send error response to client: %v", err)
				return
			}
			return
		}

		dbChirps, err = cfg.Db.GetChirpsByAuthorId(req.Context(), authorId)
		if err != nil {
			log.Printf("ERROR: Failed to get chirps from database: %v", err)
			err := utils.RespondWithError(w, http.StatusNotFound, "Failed to get chirps for that author")
			if err != nil {
				log.Printf("Failed to send error response to client: %v", err)
				return
			}
			return
		}
	}

	chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, databaseChirpToChirp(dbChirp))
	}

	err = utils.RespondWithJSON(w, http.StatusOK, chirps)
	if err != nil {
		log.Printf("ERROR: Failed to write JSON response: %v", err)
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
		log.Printf("ERROR: Failed to write JSON response: %v", err)
	}
}

func (cfg *ApiConfig) DeleteChirp(w http.ResponseWriter, req *http.Request) {
	chirpIdStr := req.PathValue("chirpId")
	chirpId, err := uuid.Parse(chirpIdStr)
	if err != nil {
		log.Printf("ERROR: Failed to parse chird id: %v", err)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Invalid chirp id")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("ERROR: Failed to get bearer token: %v", err)
		err := utils.RespondWithError(w, http.StatusBadRequest, "Bad authorization header")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	userId, err := auth.ValidateJWT(token, cfg.JwtSecret)
	if err != nil {
		log.Printf("ERROR: Failed to validate jwt token: %v", err)
		err := utils.RespondWithError(w, http.StatusForbidden, "Failed to validate user")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	chirp, err := cfg.Db.GetChirp(req.Context(), chirpId)
	if err != nil {
		log.Printf("ERROR: Failed to get chirp from database: %v", err)
		err := utils.RespondWithError(w, http.StatusNotFound, "Chirp not found")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	if chirp.UserID != userId {
		log.Printf("ERROR: Chirp's user id didn't match with user id from request: %v", err)
		err := utils.RespondWithError(w, http.StatusForbidden, "Failed to delete chirp")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	err = cfg.Db.DeleteChirp(req.Context(), chirp.ID)
	if err != nil {
		log.Printf("ERROR: Failed to delete chirp in database: %v", err)
		err := utils.RespondWithError(w, http.StatusInternalServerError, "Failed to delete chirp")
		if err != nil {
			log.Printf("Failed to send error response to client: %v", err)
			return
		}
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *ApiConfig) Reset(w http.ResponseWriter, req *http.Request) {
	if cfg.Platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	cfg.fileserverHits.Store(0)

	err := cfg.Db.DeleteUsers(req.Context())
	if err != nil {
		log.Printf("ERROR: Failed to delete users: %v", err)
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
