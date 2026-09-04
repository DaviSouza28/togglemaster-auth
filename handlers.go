package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type CreateKeyRequest struct {
	Name string `json:"name"`
}

type CreateKeyResponse struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	Message string `json:"message"`
}

func (a *App) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	}); err != nil {
		log.Println("Erro ao codificar resposta do health check")
	}
}

func (a *App) validateKeyHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	keyString := strings.TrimPrefix(authHeader, "Bearer ")

	if keyString == "" || keyString == authHeader {
		http.Error(
			w,
			"Authorization header não encontrado ou inválido",
			http.StatusUnauthorized,
		)
		return
	}

	keyHash := hashAPIKey(keyString)

	var id int

	err := a.DB.QueryRow(
		"SELECT id FROM api_keys WHERE key_hash = $1 AND is_active = true",
		keyHash,
	).Scan(&id)

	if err != nil {
		log.Println("Falha na validação de uma chave de API")

		http.Error(
			w,
			"Chave de API inválida ou inativa",
			http.StatusUnauthorized,
		)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(map[string]string{
		"message": "Chave válida",
	}); err != nil {
		log.Println("Erro ao codificar resposta de validação")
	}
}

func (a *App) createKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(
			w,
			"Método não permitido",
			http.StatusMethodNotAllowed,
		)
		return
	}

	var req CreateKeyRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(
			w,
			"Corpo da requisição inválido",
			http.StatusBadRequest,
		)
		return
	}

	req.Name = strings.TrimSpace(req.Name)

	if req.Name == "" {
		http.Error(
			w,
			"O campo 'name' é obrigatório",
			http.StatusBadRequest,
		)
		return
	}

	newKey, err := generateAPIKey()
	if err != nil {
		log.Println("Erro ao gerar nova chave de API")

		http.Error(
			w,
			"Erro ao gerar a chave",
			http.StatusInternalServerError,
		)
		return
	}

	newKeyHash := hashAPIKey(newKey)

	var newID int

	err = a.DB.QueryRow(
		"INSERT INTO api_keys (name, key_hash) VALUES ($1, $2) RETURNING id",
		req.Name,
		newKeyHash,
	).Scan(&newID)

	if err != nil {
		log.Println("Erro ao salvar nova chave de API no banco")

		http.Error(
			w,
			"Erro ao salvar a chave",
			http.StatusInternalServerError,
		)
		return
	}

	log.Printf("Nova chave de API criada com sucesso (ID: %d)", newID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(CreateKeyResponse{
		Name:    req.Name,
		Key:     newKey,
		Message: "Guarde esta chave com segurança! Você não poderá vê-la novamente.",
	}); err != nil {
		log.Println("Erro ao codificar resposta de criação de chave")
	}
}

func (a *App) masterKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		keyString := strings.TrimPrefix(authHeader, "Bearer ")

		if keyString == "" ||
			keyString == authHeader ||
			keyString != a.MasterKey {

			http.Error(
				w,
				"Acesso não autorizado",
				http.StatusForbidden,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}
