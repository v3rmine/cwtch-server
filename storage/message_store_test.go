package storage

import (
	"cwtch.im/cwtch/protocol/groups"
	"encoding/binary"
	"git.openprivacy.ca/openprivacy/log"
	"os"
	"testing"
)

func TestMessageStore(t *testing.T) {
	os.Remove("../testcwtchmessages.db")
	log.SetLevel(log.LevelDebug)
	db, err := InitializeSqliteMessageStore("../testcwtchmessages.db")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	numMessages := 100

	t.Logf("Populating Database")
	for i := 0; i < numMessages; i++ {
		buf := make([]byte, 4)
		binary.PutUvarint(buf, uint64(i))
		db.AddMessage(groups.EncryptedGroupMessage{
			Signature:  append([]byte("Hello world"), buf...),
			Ciphertext: []byte("Hello world"),
		})
		t.Logf("Inserted %v", i)
	}
	// Wait for inserts to complete..

	messages := db.FetchMessages()
	for _, message := range messages {
		t.Logf("Message: %v", message)
	}
	if len(messages) != numMessages {
		t.Fatalf("Incorrect number of messages returned")
	}

	t.Logf("Testing FetchMessagesFrom...")

	numToFetch := numMessages / 2

	buf := make([]byte, 4)
	binary.PutUvarint(buf, uint64(numToFetch))
	sig := append([]byte("Hello world"), buf...)
	messages = db.FetchMessagesFrom(sig)
	for _, message := range messages {
		t.Logf("Message: %v", message)
	}
	if len(messages) != numToFetch {
		t.Fatalf("Incorrect number of messages returned : %v", len(messages))
	}

	db.Close()
}
