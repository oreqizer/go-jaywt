package parser

import (
	"errors"
	"fmt"
	"gopkg.in/dgrijalva/jwt-go.v3"
	"net/http"
	"strings"
)

// TokenExtractor is a function retrieving the raw token string from a request.
type TokenExtractor func(r *http.Request) (string, error)

type Options struct {
	// Function that will return the Key to the JWT, public key or shared secret.
	// Defaults to nil.
	Keyfunc jwt.Keyfunc
	// Function that will extract the JWT from the request.
	// Defaults to 'Authorization' header being of the form 'Bearer <token>'
	Extractor TokenExtractor
	// Which algorithm to use.
	// Defaults to jwt.SigningMethodHS256
	SigningMethod jwt.SigningMethod
}

type JWTParser struct {
	Options *Options
}

// New returns a new JWTParser with the given options.
// It supplies default options for some fields (check Options type for details).
func New(o *Options) *JWTParser {
	if o.Extractor == nil {
		o.Extractor = FromAuthHeader
	}

	if o.SigningMethod == nil {
		o.SigningMethod = jwt.SigningMethodHS256
	}

	return &JWTParser{o}
}

// FromAuthHeader is the default extractor. It expects the 'Authorization' header
// to be in the form 'Bearer <token>'. If the header is non-existent or empty,
// it returns an empty string. Otherwise, if successful, returns the token part.
func FromAuthHeader(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", nil // No error, just no token
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("Authorization header format must be 'Bearer <token>'")
	}

	return parts[1], nil
}

// CheckJWT parses and validates the JWT token from the request. It returns
// the parsed token, if successful.
func (m *JWTParser) CheckJWT(r *http.Request) (*jwt.Token, error) {
	// Extract token
	raw, err := m.rawToken(r)
	if err != nil {
		return nil, err
	}

	// Parse token
	token, err := jwt.Parse(raw, m.Options.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("Error parsing token: %v", err)
	}

	// Check if token is valid
	if err = m.validateToken(token); err != nil {
		return nil, err
	}

	return token, nil
}

// CheckJWTWithClaims parses and validates the JWT token from the request,
// as well as the supplied claims. It returns the parsed token with the
// supplied claims, if successful.
func (m *JWTParser) CheckJWTWithClaims(r *http.Request, claims jwt.Claims) (*jwt.Token, error) {
	// Extract token
	raw, err := m.rawToken(r)
	if err != nil {
		return nil, err
	}

	// Parse token
	token, err := jwt.ParseWithClaims(raw, claims, m.Options.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("Error parsing token: %v", err)
	}

	// Check if token is valid
	if err = m.validateToken(token); err != nil {
		return nil, err
	}

	return token, nil
}

// Helper functions
// ---

func (m *JWTParser) rawToken(r *http.Request) (string, error) {
	// Extract token
	raw, err := m.Options.Extractor(r)
	if err != nil {
		return "", fmt.Errorf("Error extracting token: %v", err)
	}

	// Check if token is present
	if raw == "" {
		return "", errors.New("Required authorization token not found")
	}

	return raw, nil
}

func (m *JWTParser) validateToken(token *jwt.Token) error {
	// Verify hashing algorithm
	if m.Options.SigningMethod.Alg() != token.Header["alg"] {
		return errors.New("Error validating token algorithm")
	}

	return nil
}
