package jwtauth

import (
	"net/http"

	"testing"

	"net/http/httptest"

	"fmt"

	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

var (
	salt = []byte("test")
)

func keyFunc(token *jwt.Token) (interface{}, error) {
	return salt, nil
}

func TestJWTMiddlewareNoIgnoreURL(t *testing.T) {
	// no Authorization header test
	w := createRequest("/", http.MethodGet, nil, nil, nil, nil)
	if w.Code == http.StatusUnauthorized {
		t.Log("pass no Auhorization header")
	}

	// Authorization header test
	w = createRequest("/", http.MethodGet, jwt.SigningMethodHS256, salt, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Issuer:    "test",
	}, nil)

	if w.Code == http.StatusOK {
		t.Log("pass Auhorization header")
	}

	// Authorization header test
	w = createRequest("/", http.MethodGet, jwt.SigningMethodHS256, []byte("2333"), jwt.StandardClaims{
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Issuer:    "test",
	}, nil)

	if w.Code == http.StatusUnauthorized {
		t.Log("pass signature is invalid")
	}
}

func TestJWTMiddlewareIgnoreURL(t *testing.T) {
	w := createRequest("/", http.MethodGet, nil, nil, nil, map[string][]string{
		"/": {http.MethodGet},
	})
	if w.Code == http.StatusOK {
		t.Log("pass ignore url and http method")
	}

}

func createRequest(path, method string, expectedSignatureAlgorithm jwt.SigningMethod,
	salt []byte, c jwt.Claims, ignoreURLAndMethods map[string][]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)

	if c != nil {
		token := jwt.NewWithClaims(expectedSignatureAlgorithm, c)

		tokenString, err := token.SignedString(salt)
		if err != nil {
			panic(err)
		}

		r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", tokenString))
	}

	w := httptest.NewRecorder()
	n := createNegroniMiddleware(ignoreURLAndMethods)
	n.ServeHTTP(w, r)

	return w
}

func createNegroniMiddleware(ignoreURLAndMethods map[string][]string) *negroni.Negroni {
	router := mux.NewRouter()
	router.Path("/").HandlerFunc(indexHandler)

	n := negroni.Classic()
	n.Use(NewJWTMiddleware(keyFunc, ignoreURLAndMethods))
	n.UseHandler(router)

	return n
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello world"))
}
