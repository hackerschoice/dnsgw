package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type DomainService struct {
	cache struct {
		domains    []string
		lastUpdate time.Time
		lock       sync.RWMutex
	}
	cacheDuration  time.Duration
	watchdogCtx    context.Context
	watchdogCancel context.CancelFunc
}

func NewDomainService(ctx context.Context, cacheDuration time.Duration, watchdogInterval time.Duration) *DomainService {
	watchdogCtx, watchdogCancel := context.WithCancel(ctx)

	ds := &DomainService{
		cacheDuration:  cacheDuration,
		watchdogCtx:    watchdogCtx,
		watchdogCancel: watchdogCancel,
	}

	ds.StartWatchdog(watchdogInterval)

	log.Debugf("New DomainService watchdog started with interval: %v", watchdogInterval)

	return ds
}

func (ds *DomainService) StartWatchdog(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ds.watchdogCtx.Done():
				log.Debug("Stopping DomainService Watchdog")
				ticker.Stop()
				return
			case <-ticker.C:
				log.Debug("Calling DomainService PruneInvalidDomains")
				if err := ds.PruneInvalidDomains(); err != nil {
					log.Errorf("Error pruning invalid domains: %v", err)
				}
			}
		}
	}()
}

func (ds *DomainService) StopWatchdog() {
	ds.watchdogCancel()
}

func (ds *DomainService) PruneInvalidDomains() error {
	log.Debug("Starting PruneInvalidDomains")
	ds.cache.lock.Lock()
	log.Debug("Cache lock acquired")
	defer func() {
		ds.cache.lock.Unlock()
		log.Debug("Cache lock released")
	}()

	var userDomains []DomainEntry
	err := db.Where("is_valid = ?", true).Find(&userDomains).Error
	if err != nil {
		log.Errorf("Failed to retrieve user domains: %v", err)
		return err
	}
	log.Debugf("Retrieved %d user domains", len(userDomains))

	for _, domain := range userDomains {
		log.Debugf("Checking if domain %s points to us", domain.Domain)
		pointsToUs, err := ds.DomainPointsToUs(domain.Domain)
		if err != nil {
			log.Errorf("Error checking if domain %s points to us: %v", domain.Domain, err)
			continue
		}
		if !pointsToUs {
			log.Debugf("Domain %s does not point to us, marking as invalid", domain.Domain)
			domain.IsValid = false
			saveErr := db.Save(&domain).Error
			if saveErr != nil {
				log.Errorf("Failed to update domain status for %s: %v", domain.Domain, saveErr)
			}
		}
	}

	var validDomains []string
	err = db.Model(&DomainEntry{}).Where("is_valid = ?", true).Pluck("domain_name", &validDomains).Error
	if err != nil {
		log.Errorf("Failed to refresh domains after pruning: %v", err)
		return err
	}
	log.Debugf("Refreshed valid domains, count: %d", len(validDomains))

	ds.cache.domains = validDomains
	ds.cache.lastUpdate = time.Now()
	log.Debug("Cache updated with new valid domains")

	return nil
}

func (ds *DomainService) DomainPointsToUs(domainName string) (bool, error) {
	serverIPs, err := net.LookupIP(domainName)
	if err != nil {
		log.Errorf("Failed to lookup domain IP: %v", err)
		return false, err
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Errorf("Failed to get server IP addresses: %v", err)
		return false, err
	}

	for _, addr := range addrs {
		ipNet, isValidIpNet := addr.(*net.IPNet)
		if isValidIpNet && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				for _, ip := range serverIPs {
					if ip.Equal(ipNet.IP) {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

// Retrieves all valid domains, both admin-controlled and user-controlled
func (ds *DomainService) GetAllValidDomains() ([]string, error) {
	ds.cache.lock.RLock()
	if time.Since(ds.cache.lastUpdate) < ds.cacheDuration {
		defer ds.cache.lock.RUnlock()
		return ds.cache.domains, nil
	}
	ds.cache.lock.RUnlock()

	ds.cache.lock.Lock()
	defer ds.cache.lock.Unlock()
	if time.Since(ds.cache.lastUpdate) < ds.cacheDuration {
		return ds.cache.domains, nil
	}

	var userDomains []string
	err := db.Model(&DomainEntry{}).Where("is_valid = ?", true).Pluck("domain_name", &userDomains).Error
	if err != nil {
		return nil, err
	}

	allDomains := append(Config.DomainNames, userDomains...)
	ds.cache.domains = allDomains
	ds.cache.lastUpdate = time.Now()

	return allDomains, nil
}

func (ds *DomainService) ShouldHandle(domain string) bool {
	allDomains, err := ds.GetAllValidDomains()
	if err != nil {
		log.Errorf("Failed to retrieve domains: %v", err)
		return false
	}

	for _, validDomain := range allDomains {
		if dns.IsSubDomain(validDomain+".", domain) {
			return true
		}
	}

	return false
}

func (ds *DomainService) AddDomainEntry(newDomain string) error {
	if net.ParseIP(newDomain) != nil {
		return fmt.Errorf("invalid domain name: %s", newDomain)
	}

	domainEntry := DomainEntry{
		Domain:  newDomain,
		IsValid: true,
	}

	if err := db.Where("domain_name = ?", newDomain).First(&domainEntry).Error; err == nil {
		return fmt.Errorf("domain %s already exists in the database", newDomain)
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to check if domain %s exists in the database: %v", newDomain, err)
	}

	pointsToUs, err := ds.DomainPointsToUs(newDomain)
	if err != nil {
		return fmt.Errorf("failed to check if domain %s points to this server: %v", newDomain, err)
	}
	if !pointsToUs {
		return fmt.Errorf("domain %s does not point to this server", newDomain)
	}

	if err := db.Create(&domainEntry).Error; err != nil {
		log.Errorf("Failed to add domain %s to database: %v", newDomain, err)
		return err
	}

	ds.cache.lock.Lock()
	defer ds.cache.lock.Unlock()

	for _, domain := range ds.cache.domains {
		if domain == newDomain {
			log.Debugf("Domain %s already exists in cache", newDomain)
			return nil
		}
	}

	ds.cache.domains = append(ds.cache.domains, newDomain)
	ds.cache.lastUpdate = time.Now()

	log.Debugf("Added new domain %s to cache and database", newDomain)
	return nil
}
