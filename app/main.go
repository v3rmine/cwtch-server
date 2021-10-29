package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	cwtchserver "git.openprivacy.ca/cwtch.im/server"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	"io/ioutil"
	mrand "math/rand"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"
)

func main() {
	flagDebug := flag.Bool("debug", false, "Enable debug logging")
	flagExportTofu := flag.Bool("exportTofuBundle", false, "Export the tofubundle to a file called tofubundle")
	flag.Parse()

	log.AddEverythingFromPattern("server/app/main")
	log.AddEverythingFromPattern("server/server")
	log.ExcludeFromPattern("service.go")
	log.SetLevel(log.LevelInfo)
	if *flagDebug {
		log.Infoln("enableing Debug logging")
		log.SetLevel(log.LevelDebug)
	}
	configDir := os.Getenv("CWTCH_HOME")

	if len(os.Args) == 2 && os.Args[1] == "gen1" {
		config := new(cwtchserver.Config)
		id, pk := primitives.InitializeEphemeralIdentity()
		tid, tpk := primitives.InitializeEphemeralIdentity()
		config.PrivateKey = pk
		config.PublicKey = id.PublicKey()
		config.TokenServerPrivateKey = tpk
		config.TokenServerPublicKey = tid.PublicKey()
		config.MaxBufferLines = 100000
		config.ServerReporting = cwtchserver.Reporting{
			LogMetricsToFile:    true,
			ReportingGroupID:    "",
			ReportingServerAddr: "",
		}
		config.ConfigDir = "."
		config.FilePath = cwtchserver.ServerConfigFile
		config.Encrypted = false
		config.Save()
		return
	}

	serverConfig, err := cwtchserver.LoadCreateDefaultConfigFile(configDir, cwtchserver.ServerConfigFile, false, "")
	if err != nil {
		log.Errorf("Could not load/create config file: %s\n", err)
		return
	}
	// we don't need real randomness for the port, just to avoid a possible conflict...
	mrand.Seed(int64(time.Now().Nanosecond()))
	controlPort := mrand.Intn(1000) + 9052

	// generate a random password
	key := make([]byte, 64)
	_, err = rand.Read(key)
	if err != nil {
		panic(err)
	}

	os.MkdirAll("tordir/tor", 0700)
	tor.NewTorrc().WithHashedPassword(base64.StdEncoding.EncodeToString(key)).WithControlPort(controlPort).Build("./tordir/tor/torrc")
	acn, err := tor.NewTorACNWithAuth("tordir", "", controlPort, tor.HashedPasswordAuthenticator{Password: base64.StdEncoding.EncodeToString(key)})

	if err != nil {
		log.Errorf("\nError connecting to Tor: %v\n", err)
		os.Exit(1)
	}
	defer acn.Close()

	server := cwtchserver.NewServer(serverConfig)
	log.Infoln("starting cwtch server...")
	log.Infof("Server %s\n", server.Onion())

	log.Infof("Server bundle (import into client to use server): %s\n", log.Magenta(server.ServerBundle()))

	if *flagExportTofu {
		// Todo: change all to server export
		ioutil.WriteFile(path.Join(serverConfig.ConfigDir, "tofubundle"), []byte(server.TofuBundle()), 0600)
	}

	// Graceful Shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		server.Shutdown()
		acn.Close()
		os.Exit(1)
	}()

	server.Run(acn)
	for {
		time.Sleep(time.Second)
	}
}
