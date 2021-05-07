package storage

import (
	"cwtch.im/cwtch/protocol/groups"
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

	db.AddMessage(groups.EncryptedGroupMessage{
		Signature:  []byte("Hello world 2"),
		Ciphertext: []byte("Hello world"),
	})

	db.AddMessage(groups.EncryptedGroupMessage{
		Signature:  []byte("Hello world 1"),
		Ciphertext: []byte("Hello world"),
	})

	messages := db.FetchMessages()
	for _, message := range messages {
		t.Logf("Message: %v", message)
	}
	if len(messages) != 2 {
		t.Fatalf("Incorrect number of messages returned")
	}
	db.Close()
}
