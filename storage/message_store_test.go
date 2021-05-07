package storage

import (
	"cwtch.im/cwtch/protocol/groups"
	"cwtch.im/cwtch/server/metrics"
	"os"
	"strconv"
	"testing"
)

func TestMessageStore(t *testing.T) {
	os.Remove("ms.test")
	ms := new(MessageStore)
	counter := metrics.NewCounter()
	ms.Init("./", 1000, counter)
	for i := 0; i < 499; i++ {
		gm := groups.EncryptedGroupMessage{
			Ciphertext: []byte("Hello this is a fairly average length message that we are writing here. " + strconv.Itoa(i)),
		}
		ms.AddMessage(gm)
	}
	if counter.Count() != 499 {
		t.Errorf("Counter should be at 499 was %v", counter.Count())
	}
	ms.Close()
	ms.Init("./", 1000, counter)
	m := ms.FetchMessages()
	if len(m) != 499 {
		t.Errorf("Should have been 499 was %v", len(m))
	}

	counter.Reset()

	for i := 0; i < 1000; i++ {
		gm := groups.EncryptedGroupMessage{
			Ciphertext: []byte("Hello this is a fairly average length message that we are writing here. " + strconv.Itoa(i)),
		}
		ms.AddMessage(gm)
	}

	m = ms.FetchMessages()
	if len(m) != 1000 {
		t.Errorf("Should have been 1000 was %v", len(m))
	}
	ms.Close()
	ms.Init("./", 1000, counter)
	m = ms.FetchMessages()
	if len(m) != 999 {
		t.Errorf("Should have been 999 was %v", len(m))
	}
	ms.Close()

	os.RemoveAll("./messages")
}
