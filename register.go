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

// Register creates an account and generates an authentication token for it.
func (sys System) Register(username string, password []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hashgen")
	}

	authToken, authHash := generateAuthToken()
	if len(authToken) == 0 {
		return "", fmt.Errorf("authtoken-generror")
	}

	result, err := sys.db.Query("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)", username)
	if err == nil {
		for result.Next() {
			if result.Err() != nil {
				break
			}
			// Read the data in the current row.
			var res int
			result.Scan(&res)
			if res == 1 {
				return "", fmt.Errorf("userexists")
			}
		}
	}

	_, err = sys.db.Query("INSERT INTO users VALUES(?, ?, ?)", username, hash, authHash)
	if err != nil {
		return "", fmt.Errorf("inserterror")
	}

	return authToken, nil
}
