package main

import (
	"os/exec"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type SubdomainState struct {
	Mutex    sync.Mutex
	Starting bool
	LastSeen time.Time
	Cmd      *exec.Cmd
}

var subdomains sync.Map

func updateSubdomainState(subdomain string, cmd *exec.Cmd, starting bool) {
	now := time.Now()
	info, ok := subdomains.Load(subdomain)
	if !ok {
		subdomains.Store(subdomain, &SubdomainState{
			LastSeen: now,
			Cmd:      cmd,
			Starting: starting,
		})
	} else {
		existingInfo := info.(*SubdomainState)
		existingInfo.Mutex.Lock()
		defer existingInfo.Mutex.Unlock()
		if cmd != nil {
			existingInfo.Cmd = cmd
		}
		existingInfo.LastSeen = now
		existingInfo.Starting = starting
	}
}

func startWatchdog(timeout time.Duration) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		subdomains.Range(func(key, value interface{}) bool {
			subdomain := key.(string)
			state := value.(*SubdomainState)

			state.Mutex.Lock()
			defer state.Mutex.Unlock()

			if time.Since(state.LastSeen) > timeout && state.Cmd != nil {
				if err := state.Cmd.Process.Kill(); err != nil {
					log.Errorf("Failed to kill process for subdomain %s: %v", subdomain, err)
				} else {
					log.Infof("Killed inactive process for subdomain %s", subdomain)
					subdomains.Delete(subdomain)
				}
			}
			return true
		})
	}
}
