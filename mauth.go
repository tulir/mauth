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
	"database/sql"
)

// System is an instance of Maunium Authentication.
type System struct {
	db *sql.DB
}

// Create a System.
func Create(database *sql.DB) (System, error) {
	_, err := database.Exec("CREATE TABLE IF NOT EXISTS users (username VARCHAR(16) PRIMARY KEY, password BINARY(60) NOT NULL, authtoken BINARY(60));")
	if err != nil {
		return System{}, err
	}
	return System{database}, nil
}
