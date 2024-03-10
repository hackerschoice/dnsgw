package main

import "time"

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

type AppConfig struct {
	Dns2tcpdConfigPath string
	DomainName         string
	WatchDogTimeout    time.Duration
	AccessMode         AccessMode
}

var Config = AppConfig{
	Dns2tcpdConfigPath: "/tmp/dns-configs/",
	DomainName:         "abc.io",
	WatchDogTimeout:    15 * time.Minute,
	AccessMode:         PublicMode{},
}
