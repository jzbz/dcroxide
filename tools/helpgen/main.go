// SPDX-License-Identifier: ISC
// The dcrd -h vector generator: renders the help text dcroxide's -h
// must reproduce, through the exact path dcrd's loadConfig takes — a
// parser over the config struct (extracted verbatim from dcrd
// v1.10.7 config.go; the service group is NOT added, matching dcrd's
// dedicated help pre-parse) with the HelpFlag error written out.
//
// Regenerate the vector with:
//
//	cd tools/helpgen && go run . > ../../crates/dcroxide-node/tests/data/help_vector.txt
package main

import (
	"fmt"
	"os"
	"time"

	flags "github.com/jessevdk/go-flags"
)

type config struct {
	// General application behavior.
	ShowVersion      bool   `short:"V" long:"version" description:"Display version information and exit"`
	HomeDir          string `short:"A" long:"appdata" description:"Path to application home directory" env:"DCRD_APPDATA"`
	ConfigFile       string `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir          string `short:"b" long:"datadir" description:"Directory to store data"`
	LogDir           string `long:"logdir" description:"Directory to log output"`
	LogSize          string `long:"logsize" description:"Maximum size of log file before it is rotated"`
	NoFileLogging    bool   `long:"nofilelogging" description:"Disable file logging"`
	DbType           string `long:"dbtype" description:"Database backend to use for the block chain"`
	Profile          string `long:"profile" description:"Enable HTTP profiling on given [addr:]port -- NOTE port must be between 1024 and 65536"`
	CPUProfile       string `long:"cpuprofile" description:"Write CPU profile to the specified file"`
	MemProfile       string `long:"memprofile" description:"Write mem profile to the specified file"`
	TestNet          bool   `long:"testnet" description:"Use the test network"`
	SimNet           bool   `long:"simnet" description:"Use the simulation test network"`
	RegNet           bool   `long:"regnet" description:"Use the regression test network"`
	DebugLevel       string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`
	SigCacheMaxSize  uint   `long:"sigcachemaxsize" description:"The maximum number of entries in the signature verification cache"`
	UtxoCacheMaxSize uint   `long:"utxocachemaxsize" description:"The maximum size in MiB of the utxo cache; (min: 25, max: 32768)"`

	// RPC server options and policy.
	DisableRPC           bool     `long:"norpc" description:"Disable built-in RPC server -- NOTE: The RPC server is disabled by default if no rpcuser/rpcpass or rpclimituser/rpclimitpass is specified"`
	RPCListeners         []string `long:"rpclisten" description:"Add an interface/port to listen for RPC connections (default port: 9109, testnet: 19109)"`
	RPCUser              string   `short:"u" long:"rpcuser" description:"Username for RPC connections"`
	RPCPass              string   `short:"P" long:"rpcpass" default-mask:"-" description:"Password for RPC connections"`
	RPCAuthType          string   `long:"authtype" description:"Method for RPC client authentication (basic or clientcert)"`
	RPCClientCAs         string   `long:"clientcafile" description:"File containing Certificate Authorities to verify TLS client certificates; requires authtype=clientcert"`
	RPCLimitUser         string   `long:"rpclimituser" description:"Username for limited RPC connections"`
	RPCLimitPass         string   `long:"rpclimitpass" default-mask:"-" description:"Password for limited RPC connections"`
	RPCCert              string   `long:"rpccert" description:"File containing the certificate file"`
	RPCKey               string   `long:"rpckey" description:"File containing the certificate key"`
	TLSCurve             string   `long:"tlscurve" description:"Curve to use when generating TLS keypairs"`
	AltDNSNames          []string `long:"altdnsnames" description:"Specify additional DNS names to use when generating the RPC server certificate" env:"DCRD_ALT_DNSNAMES" env-delim:","`
	DisableTLS           bool     `long:"notls" description:"Disable TLS for the RPC server -- NOTE: This is only allowed if the RPC server is bound to localhost"`
	RPCMaxClients        int      `long:"rpcmaxclients" description:"Max number of RPC clients for standard connections"`
	RPCMaxWebsockets     int      `long:"rpcmaxwebsockets" description:"Max number of RPC websocket connections"`
	RPCMaxConcurrentReqs int      `long:"rpcmaxconcurrentreqs" description:"Max number of concurrent RPC requests that may be processed concurrently"`

	// P2P proxy and Tor settings.
	Proxy          string `long:"proxy" description:"Connect via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	ProxyUser      string `long:"proxyuser" description:"Username for proxy server"`
	ProxyPass      string `long:"proxypass" default-mask:"-" description:"Password for proxy server"`
	OnionProxy     string `long:"onion" description:"Connect to tor hidden services via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	OnionProxyUser string `long:"onionuser" description:"Username for onion proxy server"`
	OnionProxyPass string `long:"onionpass" default-mask:"-" description:"Password for onion proxy server"`
	NoOnion        bool   `long:"noonion" description:"Disable connecting to tor hidden services"`
	TorIsolation   bool   `long:"torisolation" description:"Enable Tor stream isolation by randomizing user credentials for each connection"`

	// P2P network options.
	AddPeers        []string      `short:"a" long:"addpeer" description:"Add a peer to connect with at startup"`
	ConnectPeers    []string      `long:"connect" description:"Connect only to the specified peers at startup"`
	DisableListen   bool          `long:"nolisten" description:"Disable listening for incoming connections -- NOTE: Listening is automatically disabled if the --connect or --proxy options are used without also specifying listen interfaces via --listen"`
	Listeners       []string      `long:"listen" description:"Add an interface/port to listen for connections (default all interfaces port: 9108, testnet: 19108)"`
	MaxSameIP       int           `long:"maxsameip" description:"Max number of connections with the same IP -- 0 to disable"`
	MaxPeers        int           `long:"maxpeers" description:"Max number of inbound and outbound peers"`
	DialTimeout     time.Duration `long:"dialtimeout" description:"How long to wait for TCP connection completion.  Valid time units are {s, m, h}.  Minimum 1 second"`
	PeerIdleTimeout time.Duration `long:"peeridletimeout" description:"The duration of inactivity before a peer is timed out.  Valid time units are {s,m,h}.  Minimum 15 seconds"`

	// P2P network discovery options.
	DisableSeeders bool     `long:"noseeders" description:"Disable seeding for peer discovery"`
	DisableDNSSeed bool     `long:"nodnsseed" description:"DEPRECATED: use --noseeders"`
	ExternalIPs    []string `long:"externalip" description:"Add a public-facing IP to the list of local external IPs that dcrd will advertise to other peers"`
	NoDiscoverIP   bool     `long:"nodiscoverip" description:"Disable automatic network address discovery of local external IPs"`
	Upnp           bool     `long:"upnp" description:"Use UPnP to map our listening port outside of NAT"`

	// Banning options.
	DisableBanning bool          `long:"nobanning" description:"Disable banning of misbehaving peers"`
	BanDuration    time.Duration `long:"banduration" description:"How long to ban misbehaving peers.  Valid time units are {s, m, h}.  Minimum 1 second"`
	BanThreshold   uint32        `long:"banthreshold" description:"Maximum allowed ban score before disconnecting and banning misbehaving peers"`
	Whitelists     []string      `long:"whitelist" description:"Add an IP network or IP that will not be banned (eg. 192.168.1.0/24 or ::1)"`

	// Chain related options.
	AllowOldForks  bool   `long:"allowoldforks" description:"Process forks deep in history.  Don't do this unless you know what you're doing"`
	DumpBlockchain string `long:"dumpblockchain" description:"Write blockchain as a flat file of blocks for use with addblock, to the specified filename"`
	AssumeValid    string `long:"assumevalid" description:"Hash of an assumed valid block.  Defaults to the hard-coded assumed valid block that is updated periodically with new releases.  Don't use a different hash unless you understand the implications.  Set to 0 to disable"`

	// Relay and mempool policy.
	MinRelayTxFee    float64 `long:"minrelaytxfee" description:"The minimum transaction fee in DCR/kB to be considered a non-zero fee"`
	FreeTxRelayLimit float64 `long:"limitfreerelay" description:"DEPRECATED: This behavior is no longer available and this option will be removed in a future version of the software"`
	NoRelayPriority  bool    `long:"norelaypriority" description:"DEPRECATED: This behavior is no longer available and this option will be removed in a future version of the software"`
	MaxOrphanTxs     int     `long:"maxorphantx" description:"Max number of orphan transactions to keep in memory"`
	BlocksOnly       bool    `long:"blocksonly" description:"Do not accept transactions from remote peers"`
	AcceptNonStd     bool    `long:"acceptnonstd" description:"Accept and relay non-standard transactions to the network regardless of the default settings for the active network"`
	RejectNonStd     bool    `long:"rejectnonstd" description:"Reject non-standard transactions regardless of the default settings for the active network"`
	AllowOldVotes    bool    `long:"allowoldvotes" description:"Enable the addition of very old votes to the mempool"`

	// Mining options and policy.
	Generate            bool     `long:"generate" description:"Generate (mine) coins using the CPU"`
	MiningAddrs         []string `long:"miningaddr" description:"Add the specified payment address to the list of addresses to use for generated blocks.  At least one address is required if the generate option is set"`
	BlockMinSize        uint32   `long:"blockminsize" description:"DEPRECATED: This behavior is no longer available and this option will be removed in a future version of the software"`
	BlockMaxSize        uint32   `long:"blockmaxsize" description:"Maximum block size in bytes to be used when creating a block"`
	BlockPrioritySize   uint32   `long:"blockprioritysize" description:"DEPRECATED: This behavior is no longer available and this option will be removed in a future version of the software"`
	MiningTimeOffset    int      `long:"miningtimeoffset" description:"Offset the mining timestamp of a block by this many seconds (positive values are in the past)"`
	NonAggressive       bool     `long:"nonaggressive" description:"Disable mining off of the parent block of the blockchain if there aren't enough voters"`
	NoMiningStateSync   bool     `long:"nominingstatesync" description:"Disable synchronizing the mining state with other nodes"`
	AllowUnsyncedMining bool     `long:"allowunsyncedmining" description:"Allow block templates to be generated even when the chain is not considered synced on networks other than the main network.  This is automatically enabled when the simnet option is set.  Don't do this unless you know what you're doing"`

	// Indexing options.
	TxIndex             bool `long:"txindex" description:"Maintain a full hash-based transaction index which makes all transactions available via the getrawtransaction RPC"`
	DropTxIndex         bool `long:"droptxindex" description:"Deletes the hash-based transaction index from the database on start up and then exits"`
	NoExistsAddrIndex   bool `long:"noexistsaddrindex" description:"Disable the exists address index, which tracks whether or not an address has even been used"`
	DropExistsAddrIndex bool `long:"dropexistsaddrindex" description:"Deletes the exists address index from the database on start up and then exits"`

	// IPC options.
	PipeRx          uint `long:"piperx" description:"File descriptor of read end pipe to enable parent -> child process communication"`
	PipeTx          uint `long:"pipetx" description:"File descriptor of write end pipe to enable parent <- child process communication"`
	LifetimeEvents  bool `long:"lifetimeevents" description:"Send lifetime notifications over the TX pipe"`
	BoundAddrEvents bool `long:"boundaddrevents" description:"Send notifications with the locally bound addresses of the P2P and RPC subsystems over the TX pipe"`

	// Cooked options ready for use.
}

func main() {
	var cfg config
	parser := flags.NewParser(&cfg, flags.HelpFlag)
	// dcroxide's binary name, so the usage line matches what its own
	// -h must print (dcrd renders its argv[0] the same way).
	parser.Name = "dcroxide"
	_, err := parser.ParseArgs([]string{"--help"})
	var flagsErr *flags.Error
	if ok := asFlagsErr(err, &flagsErr); !ok || flagsErr.Type != flags.ErrHelp {
		fmt.Fprintln(os.Stderr, "expected the help error")
		os.Exit(1)
	}
	fmt.Println(flagsErr.Message)
}

func asFlagsErr(err error, target **flags.Error) bool {
	e, ok := err.(*flags.Error)
	if ok {
		*target = e
	}
	return ok
}

var _ = time.Duration(0)
