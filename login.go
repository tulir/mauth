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
	result, err := sys.db.Query("SELECT password FROM users WHERE username=?;", username)
	if err == nil {
		defer result.Close()
		for result.Next() {
			if result.Err() != nil {
				break
			}
			// Read the data in the current row.
			var hash []byte
			result.Scan(&hash)
			if len(hash) != 0 {
				err = bcrypt.CompareHashAndPassword(hash, password)
				correctPassword = err == nil
			}
		}
	}
	if !correctPassword {
		return "", fmt.Errorf("incorrectpassword")
	}

	authToken, authHash := generateAuthToken()
	if len(authToken) == 0 {
		return "", fmt.Errorf("authtoken-generror")
	}

	sys.db.Query("UPDATE users SET authtoken=? WHERE username=?;", authHash, username)
	return authToken, nil
}
