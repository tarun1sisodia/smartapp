package service

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"
)

type OTPService struct {
	db *sql.DB
}

func NewOTPService(db *sql.DB) *OTPService {
	return &OTPService{db: db}
}

// GenerateOTP generates a 6-digit OTP and stores it in the database
func (s *OTPService) GenerateOTP(userID string) (string, error) {
	// Generate random 6-digit OTP
	otp := make([]byte, 3)
	if _, err := rand.Read(otp); err != nil {
		return "", fmt.Errorf("failed to generate OTP: %v", err)
	}
	otpStr := fmt.Sprintf("%06d", int(otp[0])<<16|int(otp[1])<<8|int(otp[2]))

	// Store OTP in database with expiration
	_, err := s.db.Exec(`
		INSERT INTO otp_verifications (user_id, otp_code, expires_at)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE
			otp_code = VALUES(otp_code),
			expires_at = VALUES(expires_at),
			verified = FALSE`,
		userID,
		otpStr,
		time.Now().Add(15*time.Minute), // OTP expires in 15 minutes
	)
	if err != nil {
		return "", fmt.Errorf("failed to store OTP: %v", err)
	}

	return otpStr, nil
}

// VerifyOTP verifies the provided OTP for the user
func (s *OTPService) VerifyOTP(userID, otp string) error {
	var verified bool
	var expiresAt time.Time

	err := s.db.QueryRow(`
		SELECT verified, expires_at
		FROM otp_verifications
		WHERE user_id = ? AND otp_code = ?
		ORDER BY created_at DESC
		LIMIT 1`,
		userID,
		otp,
	).Scan(&verified, &expiresAt)

	if err == sql.ErrNoRows {
		return fmt.Errorf("invalid OTP")
	} else if err != nil {
		return fmt.Errorf("failed to verify OTP: %v", err)
	}

	if verified {
		return fmt.Errorf("OTP already used")
	}

	if time.Now().After(expiresAt) {
		return fmt.Errorf("OTP expired")
	}

	// Mark OTP as verified
	_, err = s.db.Exec(`
		UPDATE otp_verifications
		SET verified = TRUE
		WHERE user_id = ? AND otp_code = ?`,
		userID,
		otp,
	)
	if err != nil {
		return fmt.Errorf("failed to update OTP status: %v", err)
	}

	// Mark user as verified
	_, err = s.db.Exec(`
		UPDATE users
		SET verified = TRUE
		WHERE id = ?`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user verification status: %v", err)
	}

	return nil
}
