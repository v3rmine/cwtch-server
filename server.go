package server

import (
	"crypto/ed25519"
	"cwtch.im/cwtch/model"
	"fmt"
	"git.openprivacy.ca/cwtch.im/server/metrics"
	"git.openprivacy.ca/cwtch.im/server/storage"
	"git.openprivacy.ca/cwtch.im/tapir"
	"git.openprivacy.ca/cwtch.im/tapir/applications"
	tor2 "git.openprivacy.ca/cwtch.im/tapir/networks/tor"
	"git.openprivacy.ca/cwtch.im/tapir/persistence"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	"path"
	"sync"
)

// Server encapsulates a complete, compliant Cwtch server.
type Server struct {
	service              tapir.Service
	config               Config
	metricsPack          metrics.Monitors
	tokenTapirService    tapir.Service
	tokenServer          *privacypass.TokenServer
	tokenService         primitives.Identity
	tokenServicePrivKey  ed25519.PrivateKey
	tokenServiceStopped  bool
	onionServiceStopped  bool
	running              bool
	existingMessageCount int
	lock                 sync.RWMutex
}

// Setup initialized a server from a given configuration
func (s *Server) Setup(serverConfig Config) {
	s.config = serverConfig
	bs := new(persistence.BoltPersistence)
	bs.Open(path.Join(serverConfig.ConfigDir, "tokens.db"))
	s.tokenServer = privacypass.NewTokenServerFromStore(&serverConfig.TokenServiceK, bs)
	log.Infof("Y: %v", s.tokenServer.Y)
	s.tokenService = s.config.TokenServiceIdentity()
	s.tokenServicePrivKey = s.config.TokenServerPrivateKey
}

// Identity returns the main onion identity of the server
func (s *Server) Identity() primitives.Identity {
	return s.config.Identity()
}

// Run starts a server with the given privateKey
func (s *Server) Run(acn connectivity.ACN) error {
	addressIdentity := tor.GetTorV3Hostname(s.config.PublicKey)
	identity := primitives.InitializeIdentity("", &s.config.PrivateKey, &s.config.PublicKey)
	var service tapir.Service
	service = new(tor2.BaseOnionService)
	service.Init(acn, s.config.PrivateKey, &identity)
	s.service = service
	log.Infof("cwtch server running on cwtch:%s\n", addressIdentity+".onion:")
	s.metricsPack.Start(service, s.config.ConfigDir, s.config.ServerReporting.LogMetricsToFile)

	ms, err := storage.InitializeSqliteMessageStore(path.Join(s.config.ConfigDir, "cwtch.messages"))
	if err != nil {
		return fmt.Errorf("could not open database: %v", err)
	}

	// Needed because we only collect metrics on a per-session basis
	// TODO fix metrics so they persist across sessions?
	s.existingMessageCount = len(ms.FetchMessages())

	s.tokenTapirService = new(tor2.BaseOnionService)
	s.tokenTapirService.Init(acn, s.tokenServicePrivKey, &s.tokenService)
	tokenApplication := new(applications.TokenApplication)
	tokenApplication.TokenService = s.tokenServer
	powTokenApp := new(applications.ApplicationChain).
		ChainApplication(new(applications.ProofOfWorkApplication), applications.SuccessfulProofOfWorkCapability).
		ChainApplication(tokenApplication, applications.HasTokensCapability)
	go func() {
		s.tokenTapirService.Listen(powTokenApp)
		s.tokenServiceStopped = true
	}()
	go func() {
		s.service.Listen(NewTokenBoardServer(ms, s.tokenServer))
		s.onionServiceStopped = true
	}()

	s.lock.Lock()
	s.running = true
	s.lock.Unlock()
	return nil
}

// KeyBundle provides the signed keybundle of the server
func (s *Server) KeyBundle() *model.KeyBundle {
	kb := model.NewKeyBundle()
	identity := s.config.Identity()
	kb.Keys[model.KeyTypeServerOnion] = model.Key(identity.Hostname())
	kb.Keys[model.KeyTypeTokenOnion] = model.Key(s.tokenService.Hostname())
	kb.Keys[model.KeyTypePrivacyPass] = model.Key(s.tokenServer.Y.String())
	kb.Sign(identity)
	return kb
}

// CheckStatus returns true if the server is running and/or an error if any part of the server needs to be restarted.
func (s *Server) CheckStatus() (bool, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.onionServiceStopped == true || s.tokenServiceStopped == true {
		return s.running, fmt.Errorf("one of more server components are down: onion:%v token service: %v", s.onionServiceStopped, s.tokenServiceStopped)
	}
	return s.running, nil
}

// Shutdown kills the app closing all connections and freeing all goroutines
func (s *Server) Shutdown() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.service.Shutdown()
	s.tokenTapirService.Shutdown()
	s.metricsPack.Stop()
	s.running = true

}

// Statistics is an encapsulation of information about the server that an operator might want to know at a glance.
type Statistics struct {
	TotalMessages int
}

// GetStatistics is a stub method for providing some high level information about
// the server operation to bundling applications (e.g. the UI)
func (s *Server) GetStatistics() Statistics {
	// TODO Statistics from Metrics is very awkward. Metrics needs an overhaul to make safe
	total := s.existingMessageCount
	if s.metricsPack.TotalMessageCounter != nil {
		total += s.metricsPack.TotalMessageCounter.Count()
	}

	return Statistics{
		TotalMessages: total,
	}
}

// ConfigureAutostart sets whether this server should autostart (in the Cwtch UI/bundling application)
func (s *Server) ConfigureAutostart(autostart bool) {
	s.config.AutoStart = autostart
	s.config.Save(s.config.ConfigDir, s.config.FilePath)
}

// Close shuts down the cwtch server in a safe way.
func (s *Server) Close() {
	log.Infof("Shutting down server")
	s.lock.Lock()
	defer s.lock.Unlock()
	log.Infof("Closing Token Server Database...")
	s.tokenServer.Close()
}
