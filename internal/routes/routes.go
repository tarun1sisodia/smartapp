package routes

import (
	"database/sql"

	"smart_attendance_server/internal/controllers"
	"smart_attendance_server/internal/middleware"
	"smart_attendance_server/internal/service"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine, db *sql.DB) {
	// Initialize services
	jwtService := service.NewJWTService()
	otpService := service.NewOTPService(db)
	emailService := service.NewEmailService()

	// Initialize controllers
	authController := controllers.NewAuthController(db, jwtService, otpService, emailService)

	// Health check endpoint
	router.GET("/api/v1/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// Public routes
	auth := router.Group("/api/v1/auth")
	{
		auth.POST("/register/teacher", authController.RegisterTeacher)
		auth.POST("/register/student", authController.RegisterStudent)
		auth.POST("/verify-otp", authController.VerifyOTP)
		auth.POST("/login/teacher", authController.TeacherLogin)
		auth.POST("/login/student", authController.StudentLogin)
		auth.POST("/login/admin", authController.AdminLogin)
	}

	// Protected routes
	api := router.Group("/api/v1")
	api.Use(middleware.AuthMiddleware(jwtService))
	{
		// Common routes
		api.POST("/auth/logout", authController.Logout)

		// Teacher routes
		teacher := api.Group("/teacher")
		teacher.Use(middleware.RoleMiddleware("teacher"))
		{
			// TODO: Add teacher-specific routes
		}

		// Student routes
		student := api.Group("/student")
		student.Use(middleware.RoleMiddleware("student"))
		{
			// TODO: Add student-specific routes
		}
	}
}
