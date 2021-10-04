package server

import (
	"crypto/rand"
	v1 "cwtch.im/cwtch/storage/v1"
	"encoding/json"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/openprivacy/log"
	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"os"
	"path"
)

const (
	// SaltFile is the standard filename to store an encrypted config's SALT under beside it
	SaltFile = "SALT"
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
	Encrypted      bool   `json:"-"`
	key            [32]byte
	MaxBufferLines int `json:"maxBufferLines"`

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

func initDefaultConfig(configDir, filename string, encrypted bool) Config {
	config := Config{Encrypted: encrypted, ConfigDir: configDir, FilePath: filename}

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

	k := new(ristretto255.Scalar)
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		// unable to generate secure random numbers
		panic("unable to generate secure random numbers")
	}
	k.FromUniformBytes(b)
	config.TokenServiceK = *k
	return config
}

// LoadCreateDefaultConfigFile loads a Config from or creates a default config and saves it to a json file specified by filename
// if the encrypted flag is true the config is store encrypted by password
func LoadCreateDefaultConfigFile(configDir, filename string, encrypted bool, password string) (*Config, error) {
	if _, err := os.Stat(path.Join(configDir, filename)); os.IsNotExist(err) {
		return CreateConfig(configDir, filename, encrypted, password)
	}
	return LoadConfig(configDir, filename, encrypted, password)
}

// CreateConfig creates a default config and saves it to a json file specified by filename
// if the encrypted flag is true the config is store encrypted by password
func CreateConfig(configDir, filename string, encrypted bool, password string) (*Config, error) {
	os.Mkdir(configDir, 0700)
	config := initDefaultConfig(configDir, filename, encrypted)
	if encrypted {
		key, _, err := v1.InitV1Directory(configDir, password)
		if err != nil {
			log.Errorf("Could not create server directory: %s", err)
			return nil, err
		}
		config.key = key
	}

	config.Save()
	return &config, nil
}

// LoadConfig loads a Config from a json file specified by filename
func LoadConfig(configDir, filename string, encrypted bool, password string) (*Config, error) {
	log.Infof("Loading config from %s\n", path.Join(configDir, filename))

	config := initDefaultConfig(configDir, filename, encrypted)

	raw, err := ioutil.ReadFile(path.Join(configDir, filename))
	if err != nil {
		return nil, err
	}

	if encrypted {
		salt, err := ioutil.ReadFile(path.Join(configDir, SaltFile))
		if err != nil {
			return nil, err
		}
		key := v1.CreateKey(password, salt)
		settingsStore := v1.NewFileStore(configDir, ServerConfigFile, key)
		raw, err = settingsStore.Read()
		if err != nil {
			return nil, err
		}
	}

	if err = json.Unmarshal(raw, &config); err != nil {
		log.Errorf("reading config: %v", err)
		return nil, err
	}

	// Always save (first time generation, new version with new variables populated)
	config.Save()
	return &config, nil
}

// Save dumps the latest version of the config to a json file given by filename
func (config *Config) Save() error {
	log.Infof("Saving config to %s\n", path.Join(config.ConfigDir, config.FilePath))
	bytes, _ := json.MarshalIndent(config, "", "\t")
	if config.Encrypted {
		settingStore := v1.NewFileStore(config.ConfigDir, config.FilePath, config.key)
		return settingStore.Write(bytes)
	}
	return ioutil.WriteFile(path.Join(config.ConfigDir, config.FilePath), bytes, 0600)
}

// CheckPassword returns true if the given password produces the same key as the current stored key, otherwise false.
func (config *Config) CheckPassword(checkpass string) bool {
	salt, err := ioutil.ReadFile(path.Join(config.ConfigDir, SaltFile))
	if err != nil {
		return false
	}
	oldkey := v1.CreateKey(checkpass, salt[:])
	return oldkey == config.key
}
