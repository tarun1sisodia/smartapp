package controllers

import (
	"database/sql"
	"net/http"

	"smart_attendance_server/internal/service"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AuthController struct {
	db           *sql.DB
	jwtService   *service.JWTService
	otpService   *service.OTPService
	emailService *service.EmailService
}

func NewAuthController(
	db *sql.DB,
	jwtService *service.JWTService,
	otpService *service.OTPService,
	emailService *service.EmailService,
) *AuthController {
	return &AuthController{
		db:           db,
		jwtService:   jwtService,
		otpService:   otpService,
		emailService: emailService,
	}
}

type RegisterTeacherRequest struct {
	FullName      string `json:"full_name" binding:"required"`
	Username      string `json:"username" binding:"required"`
	Email         string `json:"email" binding:"required,email"`
	Phone         string `json:"phone" binding:"required"`
	HighestDegree string `json:"highest_degree" binding:"required"`
	Experience    string `json:"experience" binding:"required"`
	Password      string `json:"password" binding:"required,min=6"`
}

type RegisterStudentRequest struct {
	FullName     string `json:"full_name" binding:"required"`
	RollNumber   string `json:"roll_number" binding:"required"`
	Course       string `json:"course" binding:"required"`
	AcademicYear string `json:"academic_year" binding:"required"`
	Phone        string `json:"phone" binding:"required"`
	Password     string `json:"password" binding:"required,min=6"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type StudentLoginRequest struct {
	RollNumber string `json:"roll_number" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type OTPVerificationRequest struct {
	UserID string `json:"user_id" binding:"required"`
	OTP    string `json:"otp" binding:"required,len=6"`
}

func (c *AuthController) RegisterTeacher(ctx *gin.Context) {
	var req RegisterTeacherRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
		return
	}

	// Start transaction
	tx, err := c.db.Begin()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	defer tx.Rollback()

	// Insert user
	var userID string
	err = tx.QueryRow(`
		INSERT INTO users (role, full_name, username, email, phone, highest_degree, experience, password_hash, verified)
		VALUES ('teacher', ?, ?, ?, ?, ?, ?, ?, FALSE)
		RETURNING id`,
		req.FullName, req.Username, req.Email, req.Phone, req.HighestDegree, req.Experience, hashedPassword,
	).Scan(&userID)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Generate OTP
	otp, err := c.otpService.GenerateOTP(userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	if err := tx.Commit(); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Send OTP via email
	if err := c.emailService.SendOTP(req.Email, req.FullName, otp); err != nil {
		// Log the error but don't return it to the client
		// The user can request a new OTP if they don't receive it
		// TODO: Implement proper logging
		ctx.JSON(http.StatusCreated, gin.H{
			"message": "Teacher registration successful. Please check your email for OTP.",
			"user_id": userID,
		})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{
		"message": "Teacher registration successful. Please check your email for OTP.",
		"user_id": userID,
	})
}

func (c *AuthController) RegisterStudent(ctx *gin.Context) {
	var req RegisterStudentRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
		return
	}

	// Start transaction
	tx, err := c.db.Begin()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	defer tx.Rollback()

	// Insert user
	var userID string
	err = tx.QueryRow(`
		INSERT INTO users (role, full_name, roll_number, course, academic_year, phone, password_hash, verified)
		VALUES ('student', ?, ?, ?, ?, ?, ?, FALSE)
		RETURNING id`,
		req.FullName, req.RollNumber, req.Course, req.AcademicYear, req.Phone, hashedPassword,
	).Scan(&userID)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Generate OTP
	otp, err := c.otpService.GenerateOTP(userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	if err := tx.Commit(); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Send OTP via SMS (TODO: Implement SMS service)
	// For now, just return the OTP in the response
	ctx.JSON(http.StatusCreated, gin.H{
		"message": "Student registration successful. Your OTP is: " + otp,
		"user_id": userID,
	})
}

func (c *AuthController) VerifyOTP(ctx *gin.Context) {
	var req OTPVerificationRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := c.otpService.VerifyOTP(req.UserID, req.OTP); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "OTP verified successfully",
	})
}

func (c *AuthController) TeacherLogin(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user struct {
		ID           string
		PasswordHash string
		FullName     string
		Username     string
		Role         string
	}

	err := c.db.QueryRow(`
		SELECT id, password_hash, full_name, username, role
		FROM users
		WHERE email = ? AND role = 'teacher'`,
		req.Email,
	).Scan(&user.ID, &user.PasswordHash, &user.FullName, &user.Username, &user.Role)

	if err == sql.ErrNoRows {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	} else if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token, err := c.jwtService.GenerateToken(user.ID, user.Role)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
		"user": gin.H{
			"id":        user.ID,
			"full_name": user.FullName,
			"username":  user.Username,
			"role":      user.Role,
		},
	})
}

func (c *AuthController) StudentLogin(ctx *gin.Context) {
	var req StudentLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user struct {
		ID           string
		PasswordHash string
		FullName     string
		Course       string
		AcademicYear string
		Role         string
	}

	err := c.db.QueryRow(`
		SELECT id, password_hash, full_name, course, academic_year, role
		FROM users
		WHERE roll_number = ? AND role = 'student'`,
		req.RollNumber,
	).Scan(&user.ID, &user.PasswordHash, &user.FullName, &user.Course, &user.AcademicYear, &user.Role)

	if err == sql.ErrNoRows {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	} else if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token, err := c.jwtService.GenerateToken(user.ID, user.Role)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
		"user": gin.H{
			"id":            user.ID,
			"full_name":     user.FullName,
			"course":        user.Course,
			"academic_year": user.AcademicYear,
			"role":          user.Role,
		},
	})
}

func (c *AuthController) Logout(ctx *gin.Context) {
	// Since we're using JWT tokens, we don't need to do anything server-side
	// The client should remove the token from storage
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}
