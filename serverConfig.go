package server

import (
	"crypto/rand"
	"encoding/json"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/openprivacy/log"
	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"path"
)

// Reporting is a struct for storing a the config a server needs to be a peer, and connect to a group to report
type Reporting struct {
	LogMetricsToFile    bool   `json:"logMetricsToFile"`
	ReportingGroupID    string `json:"reportingGroupId"`
	ReportingServerAddr string `json:"reportingServerAddr"`
}

// Config is a struct for storing basic server configuration
type Config struct {
	ConfigDir      string `json:"-"`
	FilePath       string `json:"-"`
	MaxBufferLines int    `json:"maxBufferLines"`

	PublicKey  ed25519.PublicKey  `json:"publicKey"`
	PrivateKey ed25519.PrivateKey `json:"privateKey"`

	TokenServerPublicKey  ed25519.PublicKey  `json:"tokenServerPublicKey"`
	TokenServerPrivateKey ed25519.PrivateKey `json:"tokenServerPrivateKey"`

	TokenServiceK ristretto255.Scalar `json:"tokenServiceK"`

	ServerReporting Reporting `json:"serverReporting"`
	AutoStart       bool      `json:"autostart"`
}

// Identity returns an encapsulation of the servers keys
func (config *Config) Identity() primitives.Identity {
	return primitives.InitializeIdentity("", &config.PrivateKey, &config.PublicKey)
}

// TokenServiceIdentity returns an encapsulation of the servers token server (experimental)
func (config *Config) TokenServiceIdentity() primitives.Identity {
	return primitives.InitializeIdentity("", &config.TokenServerPrivateKey, &config.TokenServerPublicKey)
}

// Save dumps the latest version of the config to a json file given by filename
func (config *Config) Save(dir, filename string) {
	log.Infof("Saving config to %s\n", path.Join(dir, filename))
	bytes, _ := json.MarshalIndent(config, "", "\t")
	ioutil.WriteFile(path.Join(dir, filename), bytes, 0600)
}

// LoadConfig loads a Config from a json file specified by filename
func LoadConfig(configDir, filename string) Config {
	log.Infof("Loading config from %s\n", path.Join(configDir, filename))
	config := Config{}

	id, pk := primitives.InitializeEphemeralIdentity()
	tid, tpk := primitives.InitializeEphemeralIdentity()
	config.PrivateKey = pk
	config.PublicKey = id.PublicKey()
	config.TokenServerPrivateKey = tpk
	config.TokenServerPublicKey = tid.PublicKey()
	config.MaxBufferLines = 100000
	config.ServerReporting = Reporting{
		LogMetricsToFile:    true,
		ReportingGroupID:    "",
		ReportingServerAddr: "",
	}
	config.AutoStart = false
	config.ConfigDir = configDir
	config.FilePath = filename

	k := new(ristretto255.Scalar)
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		// unable to generate secure random numbers
		panic("unable to generate secure random numbers")
	}
	k.FromUniformBytes(b)
	config.TokenServiceK = *k

	raw, err := ioutil.ReadFile(path.Join(configDir, filename))
	if err == nil {
		err = json.Unmarshal(raw, &config)

		if err != nil {
			log.Errorf("reading config: %v", err)
		}
	}
	// Always save (first time generation, new version with new variables populated)
	config.Save(configDir, filename)
	return config
}
