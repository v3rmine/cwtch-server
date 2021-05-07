package storage

import (
	"bufio"
	"cwtch.im/cwtch/protocol/groups"
	"cwtch.im/cwtch/server/metrics"
	"encoding/json"
	"fmt"
	"git.openprivacy.ca/openprivacy/log"
	"os"
	"path"
	"sync"
)

const (
	fileStorePartitions = 10
	fileStoreFilename   = "cwtch.messages"
	directory           = "messages"
)

// MessageStoreInterface defines an interface to interact with a store of cwtch messages.
type MessageStoreInterface interface {
	AddMessage(groups.EncryptedGroupMessage)
	FetchMessages() []*groups.EncryptedGroupMessage
}

// MessageStore is a file-backed implementation of MessageStoreInterface
type MessageStore struct {
	activeLogFile  *os.File
	filePos        int
	storeDirectory string
	lock           sync.Mutex
	messages       []*groups.EncryptedGroupMessage
	messageCounter metrics.Counter
	maxBufferLines int
	bufferPos      int
	bufferRotated  bool
}

// Close closes the message store and underlying resources.
func (ms *MessageStore) Close() {
	ms.lock.Lock()
	ms.messages = nil
	ms.activeLogFile.Close()
	ms.lock.Unlock()
}

func (ms *MessageStore) updateBuffer(gm *groups.EncryptedGroupMessage) {
	ms.messages[ms.bufferPos] = gm
	ms.bufferPos++
	if ms.bufferPos == ms.maxBufferLines {
		ms.bufferPos = 0
		ms.bufferRotated = true
	}
}

func (ms *MessageStore) initAndLoadFiles() error {
	ms.activeLogFile = nil
	for i := fileStorePartitions - 1; i >= 0; i-- {
		ms.filePos = 0
		filename := path.Join(ms.storeDirectory, fmt.Sprintf("%s.%d", fileStoreFilename, i))
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
		if err != nil {
			log.Errorf("MessageStore could not open: %v: %v", filename, err)
			continue
		}
		ms.activeLogFile = f

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			gms := scanner.Text()
			ms.filePos++
			gm := &groups.EncryptedGroupMessage{}
			err := json.Unmarshal([]byte(gms), gm)
			if err == nil {
				ms.updateBuffer(gm)
			}
		}
	}
	if ms.activeLogFile == nil {
		return fmt.Errorf("Could not create log file to write to in %s", ms.storeDirectory)
	}
	return nil
}

func (ms *MessageStore) updateFile(gm *groups.EncryptedGroupMessage) {
	s, err := json.Marshal(gm)
	if err != nil {
		log.Errorf("Failed to unmarshal group message %v\n", err)
	}
	fmt.Fprintf(ms.activeLogFile, "%s\n", s)
	ms.filePos++
	if ms.filePos >= ms.maxBufferLines/fileStorePartitions {
		ms.rotateFileStore()
	}
}

func (ms *MessageStore) rotateFileStore() {
	ms.activeLogFile.Close()
	os.Remove(path.Join(ms.storeDirectory, fmt.Sprintf("%s.%d", fileStoreFilename, fileStorePartitions-1)))

	for i := fileStorePartitions - 2; i >= 0; i-- {
		os.Rename(path.Join(ms.storeDirectory, fmt.Sprintf("%s.%d", fileStoreFilename, i)), path.Join(ms.storeDirectory, fmt.Sprintf("%s.%d", fileStoreFilename, i+1)))
	}

	f, err := os.OpenFile(path.Join(ms.storeDirectory, fmt.Sprintf("%s.%d", fileStoreFilename, 0)), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		log.Errorf("Could not open new message store file in: %s", ms.storeDirectory)
	}
	ms.filePos = 0
	ms.activeLogFile = f
}

// Init sets up a MessageStore of size maxBufferLines (# of messages) backed by filename
func (ms *MessageStore) Init(appDirectory string, maxBufferLines int, messageCounter metrics.Counter) error {
	ms.storeDirectory = path.Join(appDirectory, directory)
	os.Mkdir(ms.storeDirectory, 0700)

	ms.bufferPos = 0
	ms.maxBufferLines = maxBufferLines
	ms.messages = make([]*groups.EncryptedGroupMessage, maxBufferLines)
	ms.bufferRotated = false
	ms.messageCounter = messageCounter

	err := ms.initAndLoadFiles()
	return err
}

// FetchMessages returns all messages from the backing file.
func (ms *MessageStore) FetchMessages() (messages []*groups.EncryptedGroupMessage) {
	ms.lock.Lock()
	if !ms.bufferRotated {
		messages = make([]*groups.EncryptedGroupMessage, ms.bufferPos)
		copy(messages, ms.messages[0:ms.bufferPos])
	} else {
		messages = make([]*groups.EncryptedGroupMessage, ms.maxBufferLines)
		copy(messages, ms.messages[ms.bufferPos:ms.maxBufferLines])
		copy(messages[ms.bufferPos:], ms.messages[0:ms.bufferPos])
	}
	ms.lock.Unlock()
	return
}

// AddMessage adds a GroupMessage to the store
func (ms *MessageStore) AddMessage(gm groups.EncryptedGroupMessage) {
	ms.messageCounter.Add(1)
	ms.lock.Lock()
	ms.updateBuffer(&gm)
	ms.updateFile(&gm)

	ms.lock.Unlock()
}
