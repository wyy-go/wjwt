package main

import (
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/wyy-go/wjwt"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

func main() {
	// jwt auth
	auth, err := wjwt.New(wjwt.Config{
		SignConfig: wjwt.SignConfig{
			Key:        []byte("secret key"),
			Timeout:    30 * time.Second,
			MaxRefresh: 30 * time.Second,
		},

		// Lookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "cookie:<name>"
		// - "param:<name>"
		TokenLookup: "header: Authorization, query: token, cookie: jwt",
		// Lookup: "query:token",
		// Lookup: "cookie:token",

		// TokenHeaderName is a string in the header. Possible value is "Bearer"
		TokenHeaderName: "Bearer",
	})
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	service := &Service{auth}

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(service.CheckAuth("/login"))
	{
		r.POST("/login", service.Login)
		r.GET("/hello", helloHandler)
	}
	if err = http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}

type Service struct {
	auth *wjwt.Auth
}

func (sf *Service) Login(c *gin.Context) {
	var req login
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, nil)
		return
	}
	username := req.Username
	password := req.Password

	if (username == "admin" && password == "admin") ||
		(username == "test" && password == "test") {
		uid := rand.Int63()
		t, expire, err := sf.auth.Encode(&wjwt.Account{Uid: uid, Username: "admin"})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
			return
		}
		log.Printf("uid: %d, token: %s", uid, t)
		c.JSON(http.StatusOK, gin.H{"token": t, "expire": expire})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"msg": "账号或密码错"})
}

func checkPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (sf *Service) CheckAuth(excludePrefixes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !checkPrefix(c.Request.URL.Path, excludePrefixes...) {
			tk, err := sf.auth.GetToken(c)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
				return
			}
			account, err := sf.auth.Decode(tk)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
				return
			}

			//sf.auth.SetAccount(c, account)
			wjwt.SetAccount(c, account)
		}
		c.Next()
	}
}

func helloHandler(c *gin.Context) {
	account := wjwt.FromAccount(c)
	c.JSON(http.StatusOK, gin.H{
		"uid":      account.Uid,
		"username": account.Username,
		"text":     "Hello World.",
	})
}
