// go-mauth - Maunium Authentication System for Golang.
// Copyright (C) 2016 Tulir Asokan

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package mauth is the main package for the Maunium Authentication System.
package mauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

// CheckAuthToken checks if the given auth token is valid for the given user.
func (sys *System) CheckAuthToken(username string, authtoken []byte) error {
	result, err := sys.db.Query("SELECT authtoken FROM users WHERE username=?;", username)
	// Check if there was an error.
	if err == nil {
		defer result.Close()
		// Loop through the result rows.
		for result.Next() {
			// Check if the current result has an error.
			if result.Err() != nil {
				break
			}
			// Define the byte array for the password hash in the sys.db.
			var hash []byte
			// Scan the hash from the sys.db result into the previously defined byte array.
			result.Scan(&hash)
			// Make sure the scan was successful.
			if len(hash) != 0 {
				// Compare the hash and the given password.
				err = bcrypt.CompareHashAndPassword(hash, authtoken)
				if err != nil {
					return fmt.Errorf("invalid-authtoken")
				}
				return nil
			}
		}
	}
	return fmt.Errorf("invalid-authtoken")
}

func generateAuthToken() (string, []byte) {
	var authToken string
	// Create a byte array.
	b := make([]byte, 32)
	// Fill it with cryptographically random bytes.
	n, err := rand.Read(b)
	// Check if there was an error.
	if n == len(b) && err == nil {
		// Encode the bytes with base64.
		authToken = base64.RawStdEncoding.EncodeToString(b)
		if authToken == "" {
			// Generation failed, return error.
			return "", nil
		}
	}

	// Generate the bcrypt hash from the generated authentication token.
	authHash, err := bcrypt.GenerateFromPassword([]byte(authToken), bcrypt.DefaultCost-3)
	// Make sure nothing went wrong.
	if err != nil {
		// Something went wrong, return error.
		return "", nil
	}
	return authToken, authHash
}
