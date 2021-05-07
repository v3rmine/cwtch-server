package main

import (
	"crypto/rand"
	"cwtch.im/cwtch/model"
	"encoding/base64"
	cwtchserver "git.openprivacy.ca/cwtch.im/server"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	mrand "math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	serverConfigFile = "serverConfig.json"
)

func main() {
	log.AddEverythingFromPattern("server/app/main")
	log.AddEverythingFromPattern("server/server")
	log.ExcludeFromPattern("service.go")
	log.SetLevel(log.LevelDebug)
	configDir := os.Getenv("CWTCH_CONFIG_DIR")

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
		config.Save(".", "serverConfig.json")
		return
	}

	serverConfig := cwtchserver.LoadConfig(configDir, serverConfigFile)

	// we don't need real randomness for the port, just to avoid a possible conflict...
	mrand.Seed(int64(time.Now().Nanosecond()))
	controlPort := mrand.Intn(1000) + 9052

	// generate a random password
	key := make([]byte, 64)
	_, err := rand.Read(key)
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

	server := new(cwtchserver.Server)
	log.Infoln("starting cwtch server...")

	server.Setup(serverConfig)

	// TODO create a random group for testing
	group, _ := model.NewGroup(tor.GetTorV3Hostname(serverConfig.PublicKey))
	group.SignGroup([]byte{})
	invite, err := group.Invite()
	if err != nil {
		panic(err)
	}

	bundle := server.KeyBundle().Serialize()
	log.Infof("Server Config: server:%s", base64.StdEncoding.EncodeToString(bundle))

	log.Infof("Server Tofu Bundle: tofubundle:server:%s||%s", base64.StdEncoding.EncodeToString(bundle), invite)

	// Graceful Shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		acn.Close()
		server.Close()
		os.Exit(1)
	}()

	server.Run(acn)
	for {
		time.Sleep(time.Second)
	}
}
