package auth

import (
	"net/http"
)

func (h *AuthHandler) authJSONWebKeySet(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	h.writeJSON(w, http.StatusOK, h.passwords.JSONWebKeySet())
}

func (h *AuthHandler) authOpenIDConfiguration(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	h.writeJSON(w, http.StatusOK, h.passwords.OpenIDConfiguration())
}
