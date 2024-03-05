package main

import "time"

type AppConfig struct {
	Dns2tcpdConfigPath string
	DomainName         string
	WatchDogTimeout    time.Duration
}

var Config = AppConfig{
	Dns2tcpdConfigPath: "/tmp/dns-configs/",
	DomainName:         "abc.io",
	WatchDogTimeout:    15 * time.Minute,
}
