package jwtauth

import (
	"log"
	"net/http"

	"errors"

	"strings"

	"os"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrNoAuthorization     = errors.New("no authorization header")
	ErrFormatAuthorization = errors.New("authorization header format must be Bearer {token}")
)

var (
	logger = log.New(os.Stdout, "[jwt-auth] ", log.LstdFlags)
)

type JWTMiddleware struct {
	KeyFuc              jwt.Keyfunc
	IgnoreRULAndMethods map[string][]string
}

func NewJWTMiddleware(keyFunc jwt.Keyfunc, ignoreURLAndMethods map[string][]string) *JWTMiddleware {
	return &JWTMiddleware{
		KeyFuc:              keyFunc,
		IgnoreRULAndMethods: ignoreURLAndMethods,
	}
}

func (jm *JWTMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if authIgnoreURL(r.RequestURI, jm.IgnoreRULAndMethods) {
		if authIgnoreMethod(r.Method, jm.IgnoreRULAndMethods[r.RequestURI]) {
			next(w, r)
			return
		}
	}

	token, err := fromAuthHandler(r)
	if err != nil {
		logger.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
		return
	}

	if _, err := jwt.Parse(token, jm.KeyFuc); err != nil {
		logger.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
		return
	}

	next(w, r)
}

func authIgnoreURL(requestURL string, ignoreURLAndMethods map[string][]string) bool {
	for url := range ignoreURLAndMethods {
		if requestURL == url {
			return true
		}
	}

	return false
}

func authIgnoreMethod(requestMethod string, ignoreMethods []string) bool {
	for _, method := range ignoreMethods {
		if requestMethod == method {
			return true
		}
	}

	return false
}

func fromAuthHandler(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthorization
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", ErrFormatAuthorization
	}

	return authHeaderParts[1], nil
}
