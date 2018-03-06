/*
 * MIT License
 *
 * Copyright (c) 2018. Yaku Mioto
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
	for url, methods := range jm.IgnoreRULAndMethods {
		for _, method := range methods {
			if r.RequestURI == url {
				if methods == nil || r.Method == method {
					next(w, r)
					return
				}
			}
		}
	}

	token, err := fromAuthHandler(r)
	if err != nil {
		logger.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if _, err := jwt.Parse(token, jm.KeyFuc); err != nil {
		logger.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	next(w, r)
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
