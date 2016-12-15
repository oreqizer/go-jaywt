# JWT Parser

[![godoc](http://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](https://godoc.org/github.com/oreqizer/go-jwt-parser)
[![Build Status](https://travis-ci.org/oreqizer/go-jwt-parser.svg?branch=master)](https://travis-ci.org/oreqizer/go-jwt-parser)
[![codecov](https://codecov.io/gh/oreqizer/go-jwt-parser/branch/master/graph/badge.svg)](https://codecov.io/gh/oreqizer/go-jwt-parser)

A utility package that uses [jwt-go](https://github.com/dgrijalva/jwt-go) for parsing and verifying JWT tokens from requests.

> While it solves the exact problem [go-jwt-middleware](https://github.com/auth0/go-jwt-middleware) does, it doesn't have Gorilla context as a dependency and lets you use your own type of claims.

## Usage

The API basically consists of three important functions and an `Options` struct:

* Create a new parser with `parser.New(&parser.Options{})`
* Parse & verify a JWT using `parser.CheckJWT(request)`
* Parse & verify a JWT with custom claims using `parser.CheckJWTWithClaims(request, &MyClaims{})`

## Examples

Create a new parser (all options are optional):

```go
p := parser.New(&parser.Options{
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

### Parse JWT

Create any middleware you like! All you need is a `http.Request`. An example using [gin](https://github.com/gin-gonic/gin):

```go
// usage: api.Use(AuthMiddleware(p))
func AuthMiddleware(p *parser.JWTParser) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := p.CheckJWT(c.Request)
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		c.Set("userId", token.Claims.Subject)
		c.Next()
	}
}
```

### Parse JWT + custom claims

Pass your claims struct as a second argument to `CheckJWTWithClaims`:

```go
type MyClaims struct {
	Doe string `json:"doe"`
	// important to allow jwt-go built-in validation:
	jwt.StandardClaims
}

func AuthMiddleware(p *parser.JWTParser) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := p.CheckJWTWithClaims(c.Request, &MyClaims{})
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

License: **MIT**
