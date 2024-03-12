package main

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

type AccessMode interface {
	Mode() string
}

type PublicMode struct{}

func (p PublicMode) Mode() string { return "Public" }

type TokenRequiredMode struct{}

func (t TokenRequiredMode) Mode() string { return "TokenRequired" }

type PreSharedKeyMode struct {
	Key string
}

func (p PreSharedKeyMode) Mode() string { return "PreSharedKey" }

type CIDRRange struct {
	Network *net.IPNet
}

type AppConfig struct {
	Dns2tcpdConfigPath string
	TunnelDatabasePath string
	DomainName         string
	WatchDogTimeout    time.Duration
	AccessMode         AccessMode
	LogLevel           logrus.Level
	BlacklistedCIDRs   []string
}

var Config = AppConfig{
	Dns2tcpdConfigPath: "/tmp/dns-configs/",
	TunnelDatabasePath: "./tunnels.db",
	// TODO: support multiple domains
	DomainName:       "abc.io",
	WatchDogTimeout:  15 * time.Minute,
	AccessMode:       PublicMode{},
	LogLevel:         logrus.DebugLevel,
	BlacklistedCIDRs: []string{"192.168.1.0/24"},
	//BlacklistedCIDRs: []string{"192.168.1.0/24", "10.0.0.0/8", "127.0.0.0/8"},
}
