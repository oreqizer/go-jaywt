# JayWT

[![godoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/oreqizer/go-jaywt)
[![Build Status](https://travis-ci.org/oreqizer/go-jaywt.svg?branch=master)](https://travis-ci.org/oreqizer/go-jaywt)
[![codecov](https://codecov.io/gh/oreqizer/go-jaywt/branch/master/graph/badge.svg)](https://codecov.io/gh/oreqizer/go-jaywt)

A utility package that provides a DRY approach to parsing and validating JWT tokens.

> While it solves the exact problem [go-jwt-middleware](https://github.com/auth0/go-jwt-middleware) does, it doesn't have Gorilla context as a dependency and lets you use your own type of claims.

## Usage

The API basically consists of three important functions and an `Options` struct:

* Create a new instance with `jaywt.New(&jaywt.Options{})`
* Parse & verify a JWT using `jaywt.Check(request)`
* Parse & verify a JWT with custom claims using `jaywt.CheckWithClaims(request, &MyClaims{})`

### Dependencies

* [jwt-go](https://github.com/dgrijalva/jwt-go)

## Examples

Create an instance (all options are optional):

```go
j := jaywt.New(&jaywt.Options{
    // Defaults to 'nil'
    Keyfunc: func(_ *jwt.Token) (interface{}, error) {
        return []byte("secretAF"), nil
    },
    // Defaults to 'Authorization' header being: Bearer <token>
    Extractor: func(r *http.Request) (string, error) {
        return r.Header.Get("X-Authorization"), nil
    },
    // This is the default:
    SigningMethod: jwt.SigningMethodHS256,
})
```

### Check JWT

Create any middleware you like! All you need is a `http.Request`. An example using [gin](https://github.com/gin-gonic/gin):

```go
// usage: api.Use(AuthMiddleware(p))
func AuthMiddleware(j *jaywt.Core) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := j.Check(c.Request)
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		c.Set("userId", token.Claims.Subject)
		c.Next()
	}
}
```

### Check JWT with claims

Pass your claims struct as a second argument to `CheckWithClaims`:

```go
type MyClaims struct {
	Doe string `json:"doe"`
	// important to allow jwt-go built-in validation:
	jwt.StandardClaims
}

func AuthMiddleware(j *jaywt.Core) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := j.CheckWithClaims(c.Request, &MyClaims{})
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		claims, ok := token.Claims.(*MyClaims) 
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("userId", claims.Subject)
		c.Set("doe", claims.Doe)
		c.Next()
	}
}
```

---

License: **MIT**
