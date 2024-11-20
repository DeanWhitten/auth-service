package services

import (
	"auth-service/internal/models"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"time"

	"database/sql"
)

type AuthService struct {
	DB        *sql.DB
	JWTSecret string
}

// NewAuthService creates a new AuthService
func NewAuthService(db *sql.DB, jwtSecret string) *AuthService {
	return &AuthService{
		DB:        db,
		JWTSecret: jwtSecret,
	}
}

// RegisterUser handles the registration logic
func (s *AuthService) RegisterUser(email, password string) (*models.User, error) {
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create the user in the database
	return models.CreateUser(s.DB, email, string(hashedPassword))
}

// LoginUser handles the login logic and generates a JWT token
func (s *AuthService) LoginUser(email, password string) (string, error) {
	// Retrieve user by email
	user, err := models.GetUserByEmail(s.DB, email)
	if err != nil {
		return "", err
	}

	// Compare the stored hashed password with the input password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", fmt.Errorf("invalid credentials")
	}

	// Generate JWT token
	token, err := s.generateJWT(user.ID)
	if err != nil {
		return "", err
	}

	return token, nil
}

// generateJWT generates a JWT token for a user
func (s *AuthService) generateJWT(userID int64) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 24).Unix(), // Expiry time: 1 day
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return signedToken, nil
}
