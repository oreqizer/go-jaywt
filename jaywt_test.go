package jaywt_test

import (
	"errors"
	"github.com/oreqizer/go-jaywt"
	"gopkg.in/dgrijalva/jwt-go.v3"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sampleSecret = "wowSecurity9001"
const sampleSubject = "auth0|asdfomfg12345678"

func TestNewDefault(t *testing.T) {
	j := jaywt.New(&jaywt.Options{})

	if j.Options.Extractor == nil {
		t.Error("Extractor should be 'FromAuthHeader'")
	}

	inputAlg := j.Options.SigningMethod.Alg()
	wantAlg := jwt.SigningMethodHS256.Alg()
	if inputAlg != wantAlg {
		t.Errorf("SigningMethod == %s, want %s", inputAlg, wantAlg)
	}

	if j.Options.Keyfunc != nil {
		t.Error("Keyfunc must default to 'nil'")
	}
}

const customKey = "IAmACustomKeyLol"
const customExtractor = "I am the custom fn"

func TestNewCustom(t *testing.T) {
	j := jaywt.New(&jaywt.Options{
		Keyfunc: func(_ *jwt.Token) (interface{}, error) {
			return customKey, nil
		},
		Extractor: func(r *http.Request) (string, error) {
			return customExtractor, nil
		},
		SigningMethod: jwt.SigningMethodHS384,
	})

	if res, _ := j.Options.Keyfunc(nil); res != customKey {
		t.Errorf("Keyfunc: Got %s, want %s", res, customKey)
	}

	if res, _ := j.Options.Extractor(nil); res != customExtractor {
		t.Errorf("Extractor: Got %s, want %s", res, customExtractor)
	}

	inputAlg := j.Options.SigningMethod.Alg()
	wantAlg := jwt.SigningMethodHS384.Alg()
	if inputAlg != wantAlg {
		t.Errorf("SigningMethod == %s, want %s", inputAlg, wantAlg)
	}
}

const headerTokenOk = "asdf1234.asdfasdf12341234.adsf1234"
const headerOk = "Bearer " + headerTokenOk

func TestFromAuthHeaderOk(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", headerOk)

	token, err := jaywt.FromAuthHeader(req)
	if err != nil {
		t.Error(err)
		return
	}

	if token != headerTokenOk {
		t.Errorf("Token: %s, want %s", token, headerTokenOk)
	}
}

var headerTableBad = []string{
	"Bearer: noColonAllowed",
	"Berer typoHere",
	"Beerer lolWtfNoAlcohol",
	"theIntroIsMissing",
}

func TestFromAuthHeaderBad(t *testing.T) {
	for _, header := range headerTableBad {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", header)

		_, err := jaywt.FromAuthHeader(req)
		if err == nil {
			t.Errorf("Error was expected, got nil")
		}
	}
}

func TestFromAuthHeaderEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token, err := jaywt.FromAuthHeader(req)
	if err != nil {
		t.Error(err)
		return
	}

	if token != "" {
		t.Errorf("Got %s, expected empty string", token)
	}
}

func TestCheckJWTOk(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := jwt.New(jwt.SigningMethodHS256)

	token, err := raw.SignedString([]byte(sampleSecret))
	if err != nil {
		t.Error(err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: sampleKeyfunc,
	})

	_, err = p.Check(req)
	if err != nil {
		t.Error(err)
	}
}

func TestCheckJWTBadExtraction(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := jwt.New(jwt.SigningMethodHS256)

	token, err := raw.SignedString([]byte(sampleSecret))
	if err != nil {
		t.Error(err)
		return
	}

	// No 'Bearer'
	req.Header.Set("Authorization", token)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: sampleKeyfunc,
	})

	_, err = p.Check(req)
	if err == nil {
		t.Error("Expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "Error extracting") {
		t.Errorf("Got %s, want it to contain '%s'", err.Error(), "Error extracting")
	}
}

func TestCheckJWTNoToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: sampleKeyfunc,
	})

	_, err := p.Check(req)
	if err == nil {
		t.Error("Expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "token not found") {
		t.Errorf("Got %s, want it to contain '%s'", err.Error(), "token not found")
	}
}

func TestCheckJWTBadKeyfunc(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := jwt.New(jwt.SigningMethodHS256)

	token, err := raw.SignedString([]byte(sampleSecret))
	if err != nil {
		t.Error(err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: badKeyfunc,
	})

	_, err = p.Check(req)
	if err == nil {
		t.Error("Expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "Keyfunc error") {
		t.Errorf("Got %s, want it to contain '%s'", err.Error(), "Keyfunc error")
	}
}

func TestCheckJWTBadSigning(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := jwt.New(jwt.SigningMethodHS384)

	token, err := raw.SignedString([]byte(sampleSecret))
	if err != nil {
		t.Error(err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: sampleKeyfunc,
	})

	_, err = p.Check(req)
	if err == nil {
		t.Error("Expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "validating token algorithm") {
		t.Errorf("Got %s, want it to contain '%s'", err.Error(), "validating token algorithm")
	}
}

func TestCheckJWTWithClaimsOk(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Subject:   sampleSubject,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	})

	token, err := raw.SignedString([]byte(sampleSecret))
	if err != nil {
		t.Error(err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: sampleKeyfunc,
	})

	parsed, err := p.CheckWithClaims(req, &jwt.StandardClaims{})
	if err != nil {
		t.Error(err)
		return
	}

	claims, ok := parsed.Claims.(*jwt.StandardClaims)
	if !ok {
		t.Error("Claims are of wrong type")
		return
	}

	if claims.Subject != sampleSubject {
		t.Errorf("Claims subject is %s, want %s", claims.Subject, sampleSubject)
	}
}

func TestCheckJWTWithClaimsBadExtraction(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Subject:   sampleSubject,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	})

	token, err := raw.SignedString([]byte(sampleSecret))
	if err != nil {
		t.Error(err)
		return
	}

	// No 'Bearer'
	req.Header.Set("Authorization", token)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: sampleKeyfunc,
	})

	_, err = p.CheckWithClaims(req, &jwt.StandardClaims{})
	if err == nil {
		t.Error("Expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "Error extracting") {
		t.Errorf("Got %s, want it to contain '%s'", err.Error(), "Error extracting")
	}
}

func TestCheckJWTWithClaimsNoToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: sampleKeyfunc,
	})

	_, err := p.CheckWithClaims(req, &jwt.StandardClaims{})
	if err == nil {
		t.Error("Expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "token not found") {
		t.Errorf("Got %s, want it to contain '%s'", err.Error(), "token not found")
	}
}

func TestCheckJWTWithClaimsBadKeyfunc(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Subject:   sampleSubject,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	})

	token, err := raw.SignedString([]byte(sampleSecret))
	if err != nil {
		t.Error(err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: badKeyfunc,
	})

	_, err = p.CheckWithClaims(req, &jwt.StandardClaims{})
	if err == nil {
		t.Error("Expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "Keyfunc error") {
		t.Errorf("Got %s, want it to contain '%s'", err.Error(), "Keyfunc error")
	}
}

func TestCheckJWTWithClaimsBadSigning(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.StandardClaims{
		Subject:   sampleSubject,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	})

	token, err := raw.SignedString([]byte(sampleSecret))
	if err != nil {
		t.Error(err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: sampleKeyfunc,
	})

	_, err = p.CheckWithClaims(req, &jwt.StandardClaims{})
	if err == nil {
		t.Error("Expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "validating token algorithm") {
		t.Errorf("Got %s, want it to contain '%s'", err.Error(), "validating token algorithm")
	}
}

func TestCheckJWTWithClaimsInvalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Subject:   sampleSubject,
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	})

	token, err := raw.SignedString([]byte(sampleSecret))
	if err != nil {
		t.Error(err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	p := jaywt.New(&jaywt.Options{
		Keyfunc: sampleKeyfunc,
	})

	_, err = p.CheckWithClaims(req, &jwt.StandardClaims{})
	if err == nil {
		t.Error("Expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "Error parsing token") {
		t.Errorf("Got %s, want it to contain '%s'", err.Error(), "Error parsing token")
	}
}

// Helper functions
// ---

func sampleKeyfunc(_ *jwt.Token) (interface{}, error) {
	return []byte(sampleSecret), nil
}

func badKeyfunc(_ *jwt.Token) (interface{}, error) {
	return nil, errors.New("Keyfunc error")
}
