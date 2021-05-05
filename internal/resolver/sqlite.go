// Copyright (c) 2021 BitMaelum Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package resolver

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

const (
	addressTableName      = "address"
	routingTableName      = "routing"
	organisationTableName = "organisation"
)

type sqliteRepo struct {
	dsn  string
	conn *sql.DB
	mu   *sync.Mutex
}

// NewSqliteRepository creates new local repository where keys are stored in an SQLite database
func NewSqliteRepository(dsn string) (Repository, error) {
	// Work around some bugs/issues
	if !strings.HasPrefix(dsn, "file:") {
		if dsn == ":memory:" {
			dsn = "file::memory:?mode=memory&cache=shared"
		} else {
			dsn = fmt.Sprintf("file:%s?cache=shared&mode=rwc", dsn)
		}
	}

	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	db := &sqliteRepo{
		dsn:  dsn,
		conn: conn,
		mu:   new(sync.Mutex),
	}

	createTableIfNotExist(db)

	return db, nil
}

// createTableIfNotExist creates the key table if it doesn't exist already in the database
func createTableIfNotExist(db *sqliteRepo) {
	query := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (hash VARCHAR(64) PRIMARY KEY, pubkey TEXT, routing_id VARCHAR(64), deleted BOOL)", addressTableName)
	runTableQuery(db, query)

	query = fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (routing_id VARCHAR(64) PRIMARY KEY, pubkey TEXT, routing TEXT)", routingTableName)
	runTableQuery(db, query)

	query = fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (hash VARCHAR(64) PRIMARY KEY, pubkey TEXT)", organisationTableName)
	runTableQuery(db, query)
}

func runTableQuery(db *sqliteRepo, query string) {
	st, err := db.conn.Prepare(query)
	if err != nil {
		return
	}

	_, _ = st.Exec()
}

func (r *sqliteRepo) ResolveAddress(addr hash.Hash) (*AddressInfo, error) {
	var (
		h  string
		p  string
		rt string
	)

	query := fmt.Sprintf("SELECT hash, pubkey, routing_id FROM %s WHERE hash LIKE ? AND deleted=0", addressTableName)
	err := r.conn.QueryRow(query, addr.String()).Scan(&h, &p, &rt)
	if err != nil {
		return nil, err
	}

	pk, err := bmcrypto.PublicKeyFromString(p)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Hash:      h,
		PublicKey: *pk,
		RoutingID: rt,
	}, nil
}

func (r *sqliteRepo) ResolveRouting(routingID string) (*RoutingInfo, error) {
	var (
		rid string
		p   string
		rt  string
	)

	query := fmt.Sprintf("SELECT routing_id, pubkey, routing FROM %s WHERE routing_id LIKE ?", routingTableName)
	err := r.conn.QueryRow(query, routingID).Scan(&rid, &p, &rt)
	if err != nil {
		return nil, err
	}

	pk, err := bmcrypto.PublicKeyFromString(p)
	if err != nil {
		return nil, err
	}

	return &RoutingInfo{
		Hash:      rid,
		PublicKey: *pk,
		Routing:   rt,
	}, nil
}

func (r *sqliteRepo) ResolveOrganisation(orgHash hash.Hash) (*OrganisationInfo, error) {
	var (
		h string
		p string
	)

	query := fmt.Sprintf("SELECT hash, pubkey FROM %s WHERE hash LIKE ?", organisationTableName)
	err := r.conn.QueryRow(query, orgHash.String()).Scan(&h, &p)
	if err != nil {
		return nil, err
	}

	pk, err := bmcrypto.PublicKeyFromString(p)
	if err != nil {
		return nil, err
	}

	return &OrganisationInfo{
		Hash:      h,
		PublicKey: *pk,
	}, nil
}

func (r *sqliteRepo) UploadAddress(_ address.Address, info *AddressInfo, _ bmcrypto.PrivKey) error {
	query := fmt.Sprintf("INSERT INTO %s(hash, pubkey , routing_id, deleted) VALUES (?, ?, ?, 0)", addressTableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return err
	}

	_, err = st.Exec(info.Hash, info.PublicKey.String(), info.RoutingID)
	return err
}

func (r *sqliteRepo) UploadRouting(info *RoutingInfo, _ bmcrypto.PrivKey) error {
	query := fmt.Sprintf("INSERT INTO %s(routing_id, pubkey , routing) VALUES (?, ?, ?)", routingTableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return err
	}

	_, err = st.Exec(info.Hash, info.PublicKey.String(), info.Routing)
	return err
}

func (r *sqliteRepo) UploadOrganisation(info *OrganisationInfo, _ bmcrypto.PrivKey, _ proofofwork.ProofOfWork) error {
	query := fmt.Sprintf("INSERT INTO %s(hash, pubkey) VALUES (?, ?)", organisationTableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return err
	}

	_, err = st.Exec(info.Hash, info.PublicKey.String())
	return err
}

func (r *sqliteRepo) DeleteRouting(info *RoutingInfo, _ bmcrypto.PrivKey) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE routing_id LIKE ?", routingTableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return err
	}

	_, err = st.Exec(info.Hash)
	return err
}

func (r *sqliteRepo) DeleteOrganisation(info *OrganisationInfo, _ bmcrypto.PrivKey) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE hash LIKE ?", organisationTableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return err
	}

	_, err = st.Exec(info.Hash)
	return err
}

func (r *sqliteRepo) GetConfig() (*ProofOfWorkConfig, error) {
	return &ProofOfWorkConfig{
		ProofOfWork: struct {
			Address      int `json:"address"`
			Organisation int `json:"organisation"`
		}{
			Address:      22,
			Organisation: 22,
		},
	}, nil
}

func (r *sqliteRepo) CheckReserved(_ hash.Hash) ([]string, error) {
	return []string{}, nil
}

func (r *sqliteRepo) DeleteAddress(info *AddressInfo, _ bmcrypto.PrivKey) error {
	query := fmt.Sprintf("UPDATE %s SET deleted=1 WHERE hash LIKE ?", addressTableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return err
	}

	_, err = st.Exec(info.Hash)
	return err
}

func (r *sqliteRepo) UndeleteAddress(info *AddressInfo, _ bmcrypto.PrivKey) error {
	query := fmt.Sprintf("UPDATE %s SET deleted=0 WHERE hash LIKE ?", addressTableName)
	st, err := r.conn.Prepare(query)
	if err != nil {
		return err
	}

	_, err = st.Exec(info.Hash)
	return err

}
