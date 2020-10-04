package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/bitmaelum/bitmaelum-suite/internal"
	"github.com/bitmaelum/bitmaelum-suite/internal/container"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/vtolstov/jwt-go"
)

// JwtToken is a middleware that automatically verifies given JWT token
type JwtToken struct{}

type claimsContext string
type addressContext string

// ErrTokenNotValidated is returned when the token could not be validated (for any reason)
var ErrTokenNotValidated = errors.New("token could not be validated")

// Middleware JWT token authentication
func (*JwtToken) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		haddr, err := hash.NewFromHash(mux.Vars(req)["addr"])
		if err != nil {
			logrus.Trace("auth: no address specified")
			ErrorOut(w, http.StatusUnauthorized, "Cannot authorize without address")
			return
		}

		ar := container.GetAccountRepo()
		if !ar.Exists(*haddr) {
			logrus.Trace("auth: address not found")
			ErrorOut(w, http.StatusUnauthorized, "Address not found")
			return
		}

		token, err := checkToken(req.Header.Get("Authorization"), *haddr)
		if err != nil {
			logrus.Trace("auth: incorrect token: ", err)
			ErrorOut(w, http.StatusUnauthorized, "Unauthorized: "+err.Error())
			return
		}

		ctx := req.Context()
		ctx = context.WithValue(ctx, claimsContext("claims"), token.Claims)
		ctx = context.WithValue(ctx, addressContext("address"), token.Claims.(*jwt.StandardClaims).Subject)

		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

// Check if the authorization contains a valid JWT token for the given address
func checkToken(auth string, addr hash.Hash) (*jwt.Token, error) {
	if auth == "" {
		logrus.Trace("auth: empty auth string")
		return nil, ErrTokenNotValidated
	}

	if len(auth) <= 6 || strings.ToUpper(auth[0:7]) != "BEARER " {
		logrus.Trace("auth: bearer not found")
		return nil, ErrTokenNotValidated
	}
	tokenString := auth[7:]

	ar := container.GetAccountRepo()
	keys, err := ar.FetchKeys(addr)
	if err != nil {
		logrus.Trace("auth: cannot fetch keys: ", err)
		return nil, ErrTokenNotValidated
	}

	for _, key := range keys {
		token, err := internal.ValidateJWTToken(tokenString, addr, key)
		if err == nil {
			return token, nil
		}
	}

	logrus.Trace("auth: no key found that validates the token")
	return nil, ErrTokenNotValidated
}

// ErrorOut outputs an error
func ErrorOut(w http.ResponseWriter, code int, msg string) {
	type OutputResponse struct {
		Error  bool   `json:"error,omitempty"`
		Status string `json:"status"`
	}

	logrus.Debugf("Returning error (%d): %s", code, msg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(&OutputResponse{
		Error:  true,
		Status: msg,
	})
}
