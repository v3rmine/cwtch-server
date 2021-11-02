package server

import (
	"crypto/rand"
	v1 "cwtch.im/cwtch/storage/v1"
	"encoding/json"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/openprivacy/connectivity/tor"
	"git.openprivacy.ca/openprivacy/log"
	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"os"
	"path"
	"sync"
)

const (
	// SaltFile is the standard filename to store an encrypted config's SALT under beside it
	SaltFile = "SALT"

	// AttrAutostart is the attribute key for autostart setting
	AttrAutostart = "autostart"

	// AttrDescription is the attribute key for a user set server description
	AttrDescription = "description"

	// AttrStorageType is used by clients that may need info about stored server config types/styles
	AttrStorageType = "storageType"
)

const (
	// StorageTypeDefaultPassword is a AttrStorageType that indicated a app default password was used
	StorageTypeDefaultPassword = "storage-default-password"

	// StorageTypePassword is a AttrStorageType that indicated a user password was used to protect the profile
	StorageTypePassword = "storage-password"

	// StoreageTypeNoPassword is a AttrStorageType that indicated a no password was used to protect the profile
	StoreageTypeNoPassword = "storage-no-password"
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

	Attributes map[string]string `json:"attributes"`

	lock         sync.Mutex
	encFileStore v1.FileStore
}

// Identity returns an encapsulation of the servers keys
func (config *Config) Identity() primitives.Identity {
	return primitives.InitializeIdentity("", &config.PrivateKey, &config.PublicKey)
}

// TokenServiceIdentity returns an encapsulation of the servers token server (experimental)
func (config *Config) TokenServiceIdentity() primitives.Identity {
	return primitives.InitializeIdentity("", &config.TokenServerPrivateKey, &config.TokenServerPublicKey)
}

func initDefaultConfig(configDir, filename string, encrypted bool) *Config {
	config := &Config{Encrypted: encrypted, ConfigDir: configDir, FilePath: filename, Attributes: make(map[string]string)}

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
	config.Attributes[AttrAutostart] = "false"

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
	log.Debugf("CreateConfig for server with configDir: %s\n", configDir)
	os.Mkdir(configDir, 0700)
	config := initDefaultConfig(configDir, filename, encrypted)
	if encrypted {
		key, _, err := v1.InitV1Directory(configDir, password)
		if err != nil {
			log.Errorf("could not create server directory: %s", err)
			return nil, err
		}
		config.key = key
		config.encFileStore = v1.NewFileStore(configDir, ServerConfigFile, key)
	}

	config.Save()
	return config, nil
}

// LoadConfig loads a Config from a json file specified by filename
func LoadConfig(configDir, filename string, encrypted bool, password string) (*Config, error) {
	config := initDefaultConfig(configDir, filename, encrypted)
	var raw []byte
	var err error
	if encrypted {
		salt, err := ioutil.ReadFile(path.Join(configDir, SaltFile))
		if err != nil {
			return nil, err
		}
		key := v1.CreateKey(password, salt)
		config.encFileStore = v1.NewFileStore(configDir, ServerConfigFile, key)
		raw, err = config.encFileStore.Read()
		if err != nil {
			log.Errorf("read enc bytes failed: %s\n", err)
			return nil, err
		}
	} else {
		raw, err = ioutil.ReadFile(path.Join(configDir, filename))
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
	return config, nil
}

// Save dumps the latest version of the config to a json file given by filename
func (config *Config) Save() error {
	config.lock.Lock()
	defer config.lock.Unlock()
	bytes, _ := json.MarshalIndent(config, "", "\t")
	if config.Encrypted {
		return config.encFileStore.Write(bytes)
	}
	return ioutil.WriteFile(path.Join(config.ConfigDir, config.FilePath), bytes, 0600)
}

// CheckPassword returns true if the given password produces the same key as the current stored key, otherwise false.
func (config *Config) CheckPassword(checkpass string) bool {
	config.lock.Lock()
	defer config.lock.Unlock()
	salt, err := ioutil.ReadFile(path.Join(config.ConfigDir, SaltFile))
	if err != nil {
		return false
	}
	oldkey := v1.CreateKey(checkpass, salt[:])
	return oldkey == config.key
}

// Onion returns the .onion url for the server
func (config *Config) Onion() string {
	config.lock.Lock()
	defer config.lock.Unlock()
	return tor.GetTorV3Hostname(config.PublicKey) + ".onion"
}

// SetAttribute sets a server attribute
func (config *Config) SetAttribute(key, val string) {
	config.lock.Lock()
	config.Attributes[key] = val
	config.lock.Unlock()
	config.Save()
}

// GetAttribute gets a server attribute
func (config *Config) GetAttribute(key string) string {
	config.lock.Lock()
	defer config.lock.Unlock()
	return config.Attributes[key]
}
