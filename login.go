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
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

// Login generates an authentication token for the user.
func (sys *System) Login(username string, password []byte) (string, error) {
	var correctPassword = false
	// Get the password of the given user.
	result, err := sys.db.Query("SELECT password FROM users WHERE username=?;", username)
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
				err = bcrypt.CompareHashAndPassword(hash, password)
				// Set the correctPassword field to the correct value.
				correctPassword = err == nil
			}
		}
	}
	// Check if the password was correct.
	if !correctPassword {
		// Return error if the password was wrong.
		return "", fmt.Errorf("incorrectpassword")
	}

	authToken, authHash := generateAuthToken()
	if len(authToken) == 0 {
		return "", fmt.Errorf("authtoken-generror")
	}

	// Update sys.db.
	sys.db.Query("UPDATE users SET authtoken=? WHERE username=?;", authHash, username)
	// Return auth token.
	return authToken, nil
}
