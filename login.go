// mauth - Maunium Authentication System for Golang.
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
	"net/http"
)

// Login generates an authentication token for the user.
func (sys System) Login(username string, password []byte) (string, error) {
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

// LoginHTTP handles a HTTP login request.
func (sys System) LoginHTTP(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		w.Header().Add("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return fmt.Errorf("illegalmethod")
	}
	decoder := decoder(r.Body)
	var af AuthForm
	err := decoder.Decode(&af)
	if err != nil || len(af.Password) == 0 || len(af.Username) == 0 {
		//log.Debugf("%[1]s sent an invalid login request.", ip)
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("invalidrequest")
	}
	authToken, err := sys.Login(af.Username, []byte(af.Password))
	if err != nil {
		if err.Error() == "incorrectpassword" {
			//log.Debugf("%[1]s tried to log in as %[2]s with the incorrect password.", ip, af.Username)
			output(w, AuthResponse{Error: "incorrectpassword", ErrorReadable: "The username or password was incorrect."}, http.StatusUnauthorized)
			return fmt.Errorf("incorrectpassword")
		}
		//log.Errorf("Login error: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	//log.Debugf("%[1]s logged in as %[2]s successfully.", ip, af.Username)
	output(w, AuthResponse{AuthToken: authToken}, http.StatusOK)
	return nil
}
