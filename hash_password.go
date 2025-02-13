package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	password := []byte("project@2025")
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("Error generating hash: %v\n", err)
		return
	}
	fmt.Printf("%s\n", hash)
}
