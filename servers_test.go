package server

import (
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/log"
	"os"
	"testing"
)

const TestDir = "./serversTest"
const DefaultPassword = "be gay do crime"

const TestServerDesc = "a test Server"

func TestServers(t *testing.T) {
	log.SetLevel(log.LevelDebug)
	log.Infof("clean up / setup...\n")
	os.RemoveAll(TestDir)
	os.Mkdir(TestDir, 0700)

	acn := connectivity.NewLocalACN()
	log.Infof("NewServers()...\n")
	servers := NewServers(acn, TestDir)
	s, err := servers.CreateServer(DefaultPassword)
	if err != nil {
		t.Errorf("could not create server: %s", err)
		return
	}
	s.SetAttribute(AttrDescription, TestServerDesc)
	serverOnion := s.Onion()

	s.Shutdown()

	log.Infof("NewServers()...\n" )
	servers2 := NewServers(acn, TestDir)
	log.Infof("LoadServers()...\n")
	list, err := servers2.LoadServers(DefaultPassword)
	log.Infof("Loaded!\n")
	if err != nil {
		t.Errorf("clould not load server: %s", err)
		return
	}
	if len(list) != 1 {
		t.Errorf("expected to load 1 server, got %d", len(list))
		return
	}

	if list[0] != serverOnion {
		t.Errorf("expected loaded server to have onion: %s but got %s", serverOnion, list[0])
	}

	s1 := servers.GetServer(list[0])
	if s1.GetAttribute(AttrDescription) != TestServerDesc {
		t.Errorf("expected server description of '%s' but got '%s'", TestServerDesc, s1.GetAttribute(AttrDescription))
	}

	servers2.Shutdown()
	os.RemoveAll(TestDir)
}