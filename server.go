package server

import (
	"crypto/ed25519"
	"cwtch.im/cwtch/model"
	"encoding/base64"
	"encoding/binary"
	"errors"
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
	"os"
	"path"
	"strings"
	"sync"
)

const (
	// ServerConfigFile is the standard filename for a server's config to be written to in a directory
	ServerConfigFile = "serverConfig.json"
)

// Server encapsulates a complete, compliant Cwtch server.
type Server interface {
	Identity() primitives.Identity
	Run(acn connectivity.ACN) error
	KeyBundle() *model.KeyBundle
	CheckStatus() (bool, error)
	Shutdown()
	GetStatistics() Statistics
	ConfigureAutostart(autostart bool)
	Close()
	Delete(password string) error
	Onion() string
	Server() string
	TofuBundle() string
	HashName() string
}

type server struct {
	service              tapir.Service
	config               *Config
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

// NewServer creates and configures a new server based on the supplied configuration
func NewServer(serverConfig *Config) Server {
	server := new(server)
	server.running = false
	server.config = serverConfig
	bs := new(persistence.BoltPersistence)
	bs.Open(path.Join(serverConfig.ConfigDir, "tokens.db"))
	server.tokenServer = privacypass.NewTokenServerFromStore(&serverConfig.TokenServiceK, bs)
	log.Infof("Y: %v", server.tokenServer.Y)
	server.tokenService = server.config.TokenServiceIdentity()
	server.tokenServicePrivKey = server.config.TokenServerPrivateKey
	return server
}

// Identity returns the main onion identity of the server
func (s *server) Identity() primitives.Identity {
	return s.config.Identity()
}

// Run starts a server with the given privateKey
func (s *server) Run(acn connectivity.ACN) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.running {
		return nil
	}

	identity := primitives.InitializeIdentity("", &s.config.PrivateKey, &s.config.PublicKey)
	var service tapir.Service
	service = new(tor2.BaseOnionService)
	service.Init(acn, s.config.PrivateKey, &identity)
	s.service = service
	log.Infof("cwtch server running on cwtch:%s\n", s.Onion())
	s.metricsPack.Start(service, s.config.ConfigDir, s.config.ServerReporting.LogMetricsToFile)

	ms, err := storage.InitializeSqliteMessageStore(path.Join(s.config.ConfigDir, "cwtch.messages"), s.metricsPack.MessageCounter)
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

	s.running = true
	return nil
}

// KeyBundle provides the signed keybundle of the server
func (s *server) KeyBundle() *model.KeyBundle {
	kb := model.NewKeyBundle()
	identity := s.config.Identity()
	kb.Keys[model.KeyTypeServerOnion] = model.Key(identity.Hostname())
	kb.Keys[model.KeyTypeTokenOnion] = model.Key(s.tokenService.Hostname())
	kb.Keys[model.KeyTypePrivacyPass] = model.Key(s.tokenServer.Y.String())
	kb.Sign(identity)
	return kb
}

// CheckStatus returns true if the server is running and/or an error if any part of the server needs to be restarted.
func (s *server) CheckStatus() (bool, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.onionServiceStopped == true || s.tokenServiceStopped == true {
		return s.running, fmt.Errorf("one of more server components are down: onion:%v token service: %v", s.onionServiceStopped, s.tokenServiceStopped)
	}
	return s.running, nil
}

// Shutdown kills the app closing all connections and freeing all goroutines
func (s *server) Shutdown() {
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
func (s *server) GetStatistics() Statistics {
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
func (s *server) ConfigureAutostart(autostart bool) {
	s.config.AutoStart = autostart
	s.config.Save()
}

// Close shuts down the cwtch server in a safe way.
func (s *server) Close() {
	log.Infof("Shutting down server")
	s.lock.Lock()
	defer s.lock.Unlock()
	log.Infof("Closing Token server Database...")
	s.tokenServer.Close()
}

func (s *server) Delete(password string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.config.Encrypted && !s.config.CheckPassword(password) {
		return errors.New("Cannot delete server, passwords do not match")
	}
	os.RemoveAll(s.config.ConfigDir)
	return nil
}

func (s *server) Onion() string {
	return tor.GetTorV3Hostname(s.config.PublicKey) + ".onion"
}

func (s *server) Server() string {
	bundle := s.KeyBundle().Serialize()
	return fmt.Sprintf("server:%s", base64.StdEncoding.EncodeToString(bundle))
}

func (s *server) TofuBundle() string {
	group, _ := model.NewGroup(tor.GetTorV3Hostname(s.config.PublicKey))
	invite, err := group.Invite()
	if err != nil {
		panic(err)
	}
	bundle := s.KeyBundle().Serialize()
	return fmt.Sprintf("tofubundle:server:%s||%s", base64.StdEncoding.EncodeToString(bundle), invite)
}

// TODO demo implementation only, not nearly enough entropy
// TODO Apache license
// https://github.com/dustinkirkland/petname/blob/master/usr/share/petname/small/names.txt
var namesSmall = []string{"ox", "ant", "ape", "asp", "bat", "bee", "boa", "bug", "cat", "cod", "cow", "cub", "doe", "dog", "eel", "eft", "elf", "elk", "emu", "ewe", "fly", "fox", "gar", "gnu", "hen", "hog", "imp", "jay", "kid", "kit", "koi", "lab", "man", "owl", "pig", "pug", "pup", "ram", "rat", "ray", "yak", "bass", "bear", "bird", "boar", "buck", "bull", "calf", "chow", "clam", "colt", "crab", "crow", "dane", "deer", "dodo", "dory", "dove", "drum", "duck", "fawn", "fish", "flea", "foal", "fowl", "frog", "gnat", "goat", "grub", "gull", "hare", "hawk", "ibex", "joey", "kite", "kiwi", "lamb", "lark", "lion", "loon", "lynx", "mako", "mink", "mite", "mole", "moth", "mule", "mutt", "newt", "orca", "oryx", "pika", "pony", "puma", "seal", "shad", "slug", "sole", "stag", "stud", "swan", "tahr", "teal", "tick", "toad", "tuna", "wasp", "wolf", "worm", "wren", "yeti", "adder", "akita", "alien", "aphid", "bison", "boxer", "bream", "bunny", "burro", "camel", "chimp", "civet", "cobra", "coral", "corgi", "crane", "dingo", "drake", "eagle", "egret", "filly", "finch", "gator", "gecko", "ghost", "ghoul", "goose", "guppy", "heron", "hippo", "horse", "hound", "husky", "hyena", "koala", "krill", "leech", "lemur", "liger", "llama", "louse", "macaw", "midge", "molly", "moose", "moray", "mouse", "panda", "perch", "prawn", "quail", "racer", "raven", "rhino", "robin", "satyr", "shark", "sheep", "shrew", "skink", "skunk", "sloth", "snail", "snake", "snipe", "squid", "stork", "swift", "swine", "tapir", "tetra", "tiger", "troll", "trout", "viper", "wahoo", "whale", "zebra", "alpaca", "amoeba", "baboon", "badger", "beagle", "bedbug", "beetle", "bengal", "bobcat", "caiman", "cattle", "cicada", "collie", "condor", "cougar", "coyote", "dassie", "donkey", "dragon", "earwig", "falcon", "feline", "ferret", "gannet", "gibbon", "glider", "goblin", "gopher", "grouse", "guinea", "hermit", "hornet", "iguana", "impala", "insect", "jackal", "jaguar", "jennet", "kitten", "kodiak", "lizard", "locust", "maggot", "magpie", "mammal", "mantis", "marlin", "marmot", "marten", "martin", "mayfly", "minnow", "monkey", "mullet", "muskox", "ocelot", "oriole", "osprey", "oyster", "parrot", "pigeon", "piglet", "poodle", "possum", "python", "quagga", "rabbit", "raptor", "rodent", "roughy", "salmon", "sawfly", "serval", "shiner", "shrimp", "spider", "sponge", "tarpon", "thrush", "tomcat", "toucan", "turkey", "turtle", "urchin", "vervet", "walrus", "weasel", "weevil", "wombat", "anchovy", "anemone", "bluejay", "buffalo", "bulldog", "buzzard", "caribou", "catfish", "chamois", "cheetah", "chicken", "chigger", "cowbird", "crappie", "crawdad", "cricket", "dogfish", "dolphin", "firefly", "garfish", "gazelle", "gelding", "giraffe", "gobbler", "gorilla", "goshawk", "grackle", "griffon", "grizzly", "grouper", "haddock", "hagfish", "halibut", "hamster", "herring", "jackass", "javelin", "jawfish", "jaybird", "katydid", "ladybug", "lamprey", "lemming", "leopard", "lioness", "lobster", "macaque", "mallard", "mammoth", "manatee", "mastiff", "meerkat", "mollusk", "monarch", "mongrel", "monitor", "monster", "mudfish", "muskrat", "mustang", "narwhal", "oarfish", "octopus", "opossum", "ostrich", "panther", "peacock", "pegasus", "pelican", "penguin", "phoenix", "piranha", "polecat", "primate", "quetzal", "raccoon", "rattler", "redbird", "redfish", "reptile", "rooster", "sawfish", "sculpin", "seagull", "skylark", "snapper", "spaniel", "sparrow", "sunbeam", "sunbird", "sunfish", "tadpole", "termite", "terrier", "unicorn", "vulture", "wallaby", "walleye", "warthog", "whippet", "wildcat", "aardvark", "airedale", "albacore", "anteater", "antelope", "arachnid", "barnacle", "basilisk", "blowfish", "bluebird", "bluegill", "bonefish", "bullfrog", "cardinal", "chipmunk", "cockatoo", "crayfish", "dinosaur", "doberman", "duckling", "elephant", "escargot", "flamingo", "flounder", "foxhound", "glowworm", "goldfish", "grubworm", "hedgehog", "honeybee", "hookworm", "humpback", "kangaroo", "killdeer", "kingfish", "labrador", "lacewing", "ladybird", "lionfish", "longhorn", "mackerel", "malamute", "marmoset", "mastodon", "moccasin", "mongoose", "monkfish", "mosquito", "pangolin", "parakeet", "pheasant", "pipefish", "platypus", "polliwog", "porpoise", "reindeer", "ringtail", "sailfish", "scorpion", "seahorse", "seasnail", "sheepdog", "shepherd", "silkworm", "squirrel", "stallion", "starfish", "starling", "stingray", "stinkbug", "sturgeon", "terrapin", "titmouse", "tortoise", "treefrog", "werewolf", "woodcock"}

func (s *server) HashName() string {
	var bytes []byte = s.config.PublicKey
	var words []string
	for i := 0; i < 8; i++ {
		index := int(binary.BigEndian.Uint32(bytes[i*4:(i+1)*4])) % len(namesSmall)
		words = append(words, namesSmall[index])
	}
	return strings.Join(words, "-")
}
