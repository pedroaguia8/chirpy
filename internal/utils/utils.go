package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) error {
	response, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("couldn't marshal data to json: %w", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(code)
	_, err = w.Write(response)
	if err != nil {
		return fmt.Errorf("error writing data to response: %w", err)
	}
	return nil
}

func RespondWithError(w http.ResponseWriter, code int, msg string) error {
	return RespondWithJSON(w, code, map[string]string{"error": msg})
}

func FilterProfanity(text string) string {
	profanity := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}

	words := strings.Split(text, " ")
	for i, word := range words {
		if _, ok := profanity[strings.ToLower(word)]; ok {
			words[i] = "****"
		}
	}
	filteredText := strings.Join(words, " ")
	return filteredText
}
