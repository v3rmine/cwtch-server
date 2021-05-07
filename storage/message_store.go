package storage

import (
	"cwtch.im/cwtch/protocol/groups"
	"database/sql"
	"encoding/base64"
	"fmt"
	"git.openprivacy.ca/openprivacy/log"
	_ "github.com/mattn/go-sqlite3" // sqlite3 driver
)

// MessageStoreInterface defines an interface to interact with a store of cwtch messages.
type MessageStoreInterface interface {
	AddMessage(groups.EncryptedGroupMessage)
	FetchMessages() []*groups.EncryptedGroupMessage
	FetchMessagesFrom(signature []byte) []*groups.EncryptedGroupMessage
}

// SqliteMessageStore is an sqlite3 backed message store
type SqliteMessageStore struct {
	database *sql.DB

	// Some prepared queries...
	preparedInsertStatement *sql.Stmt // A Stmt is safe for concurrent use by multiple goroutines.
	preparedFetchFromQuery  *sql.Stmt
}

// Close closes the underlying sqlite3 database to further changes
func (s *SqliteMessageStore) Close() {
	s.preparedInsertStatement.Close()
	s.preparedFetchFromQuery.Close()
	s.database.Close()
}

// AddMessage implements the MessageStoreInterface AddMessage for sqlite message store
func (s *SqliteMessageStore) AddMessage(message groups.EncryptedGroupMessage) {
	stmt, err := s.preparedInsertStatement.Exec(base64.StdEncoding.EncodeToString(message.Signature), base64.StdEncoding.EncodeToString(message.Ciphertext))
	if err != nil {
		log.Errorf("%v %q", stmt, err)
		return
	}
}

// FetchMessages implements the MessageStoreInterface FetchMessages for sqlite message store
func (s SqliteMessageStore) FetchMessages() []*groups.EncryptedGroupMessage {
	rows, err := s.database.Query("SELECT id, signature,ciphertext from messages")
	if err != nil {
		log.Errorf("%v", err)
		return nil
	}
	defer rows.Close()
	return s.compileRows(rows)
}

// FetchMessagesFrom implements the MessageStoreInterface FetchMessagesFrom for sqlite message store
func (s SqliteMessageStore) FetchMessagesFrom(signature []byte) []*groups.EncryptedGroupMessage {
	if signature == nil {
		return s.FetchMessages()
	}

	rows, err := s.preparedFetchFromQuery.Query(base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		log.Errorf("%v", err)
		return nil
	}
	defer rows.Close()
	return s.compileRows(rows)
}

func (s *SqliteMessageStore) compileRows(rows *sql.Rows) []*groups.EncryptedGroupMessage {
	var messages []*groups.EncryptedGroupMessage
	for rows.Next() {
		var id int
		var signature string
		var ciphertext string
		err := rows.Scan(&id, &signature, &ciphertext)
		if err != nil {
			log.Errorf("Error fetching row %v", err)
		}
		rawSignature, _ := base64.StdEncoding.DecodeString(signature)
		rawCiphertext, _ := base64.StdEncoding.DecodeString(ciphertext)
		messages = append(messages, &groups.EncryptedGroupMessage{
			Signature:  rawSignature,
			Ciphertext: rawCiphertext,
		})
	}
	return messages
}

// InitializeSqliteMessageStore creates a database `dbfile` with the necessary tables (if it doesn't already exist)
// and returns an open database
func InitializeSqliteMessageStore(dbfile string) (*SqliteMessageStore, error) {
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		log.Errorf("database %v cannot be created or opened %v", dbfile, err)
		return nil, fmt.Errorf("database %v cannot be created or opened: %v", dbfile, err)
	}
	sqlStmt := `CREATE TABLE IF NOT EXISTS  messages (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, signature TEXT UNIQUE NOT NULL, ciphertext TEXT NOT NULL);`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		db.Close()
		log.Errorf("%q: %s", err, sqlStmt)
		return nil, fmt.Errorf("%s: %q", sqlStmt, err)
	}
	log.Infof("Database Initialized")
	slms := new(SqliteMessageStore)
	slms.database = db

	sqlStmt = `INSERT INTO messages(signature, ciphertext) values (?,?);`
	stmt, err := slms.database.Prepare(sqlStmt)
	if err != nil {
		log.Errorf("%q: %s", err, sqlStmt)
		return nil, fmt.Errorf("%s: %q", sqlStmt, err)
	}
	slms.preparedInsertStatement = stmt

	query, err := slms.database.Prepare("SELECT id, signature,ciphertext FROM messages WHERE id>=(SELECT id FROM messages WHERE signature=(?));")
	if err != nil {
		log.Errorf("%v", err)
		return nil, fmt.Errorf("%s: %q", sqlStmt, err)
	}
	slms.preparedFetchFromQuery = query

	return slms, nil
}
