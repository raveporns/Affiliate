package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// Public Key ในรูปแบบ PEM (คัดลอกจาก Keycloak)
var publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnnll1sAdTskoJWjW9SviOpUYyUG6KpdG1nPcg5XqxV5VY/E/fN/9i7VKHjqfawTsqk45MOS3wt33bprL9glmd1msQHdC2RRSpaGctYGK6UH8UK/Zrhuit8HvRtmtwcQeT8rPjU+/NO0gj4b7z8BLSE8aOpai+f70KZnK9bGdSTJr0K5s6Xdf51k5vmVdExX/6/WPzWpEXc8EdNKw0ES4s4Kwc9F01D1JeaVov5WbWrZpYI/husxCNua9FZF/CTPjXq5uVy/FPkPczqh4GO+6/b/O8jQ1a9VxzatWEGG6vvckMo0W42ZwW1lLia1jF1Dee3vjdZDZEwrUIK91FVmB0QIDAQAB
-----END PUBLIC KEY-----`

// Global variable สำหรับเก็บ *rsa.PublicKey ที่แปลงแล้ว
var rsaPublicKey *rsa.PublicKey

// Casbin enforcer
var enforcer *casbin.Enforcer

func init() {
	var err error
	// สร้าง Casbin enforcer
	enforcer, err = casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		panic("failed to create casbin enforcer: " + err.Error())
	}

	// Decode PEM และ parse public key เพียงครั้งเดียวตอนเริ่มต้น
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	var ok bool
	rsaPublicKey, ok = pub.(*rsa.PublicKey)
	if !ok {
		panic("key is not of type *rsa.PublicKey")
	}
}

func main() {
	r := gin.Default()

	// เพิ่ม CORS middleware
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// เส้นทางที่มีการป้องกัน
	protected := r.Group("/api")
	protected.Use(JWTAuthMiddleware())
	{
		protected.GET("/data", func(c *gin.Context) {
			username := c.GetString("username")
			roles := c.GetStringSlice("roles")
			c.JSON(200, gin.H{
				"data":     "This is protected data",
				"username": username,
				"roles":    roles,
			})
		})
	}

	r.Run(":8081")
}

// Middleware สำหรับตรวจสอบ JWT และสิทธิ์ด้วย Casbin
func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse JWT โดยใช้ rsaPublicKey ที่แปลงแล้วจากขั้นตอน initial setup
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return rsaPublicKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// ดึง claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// ตรวจสอบเวลาหมดอายุของโทเค็น
		if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
			c.JSON(401, gin.H{"error": "Token expired"})
			c.Abort()
			return
		}

		// ตรวจสอบผู้ออกโทเค็น
		if !claims.VerifyIssuer("http://localhost:8088/realms/affiliate", true) {
			c.JSON(401, gin.H{"error": "Invalid token issuer"})
			c.Abort()
			return
		}

		// ดึง username จาก claims
		username, ok := claims["preferred_username"].(string)
		if !ok {
			c.JSON(401, gin.H{"error": "Username not found in token"})
			c.Abort()
			return
		}

		// ดึง roles จาก realm_access.roles ซึ่งอาจมีหลาย role
		realmAccess, ok := claims["realm_access"].(map[string]interface{})
		if !ok {
			c.JSON(401, gin.H{"error": "Roles not found in token"})
			c.Abort()
			return
		}
		rawRoles, ok := realmAccess["roles"].([]interface{})
		if !ok || len(rawRoles) == 0 {
			c.JSON(401, gin.H{"error": "No roles found in token"})
			c.Abort()
			return
		}

		// ดึง role ทั้งหมดจาก payload
		var rolesList []string
		for _, r := range rawRoles {
			if roleStr, ok := r.(string); ok {
				rolesList = append(rolesList, roleStr)
			}
		}

		// ตรวจสอบสิทธิ์ด้วย Casbin: ให้ตรวจสอบว่ามี role ใดที่อนุญาตให้เข้าถึง resource ได้หรือไม่
		resource := c.Request.URL.Path // เช่น /api/data
		action := c.Request.Method     // เช่น GET
		allowed := false
		for _, role := range rolesList {
			permit, err := enforcer.Enforce(role, resource, action)
			if err != nil {
				c.JSON(500, gin.H{"error": "Error checking permission"})
				c.Abort()
				return
			}
			if permit {
				allowed = true
				break
			}
		}
		if !allowed {
			c.JSON(403, gin.H{"error": "Forbidden: Insufficient permissions"})
			c.Abort()
			return
		}

		// ส่ง username และ roles ไปยัง handler
		c.Set("username", username)
		c.Set("roles", rolesList)
		c.Next()
	}
}
