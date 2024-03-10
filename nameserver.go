package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type DNSRecord struct {
	Subdomain string
	IP        string
	CreatedAt time.Time
}

func insertDNSRecord(subdomain, ip string) error {
	dnsRecord := DNSRecord{
		Subdomain: subdomain,
		IP:        ip,
		CreatedAt: time.Now(),
	}
	result := db.Create(&dnsRecord)
	return result.Error
}

func generateRandomSubdomain() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func createNsEntry(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP address is required"})
		return
	}

	subdomain := generateRandomSubdomain()
	err := setAsNameserver(subdomain, ip)
	if err != nil {
		log.Errorf("Failed to set %s as nameserver for %s: %v", ip, subdomain, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set as nameserver"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Set %s as nameserver for %s", ip, subdomain)})
}

func setAsNameserver(subdomain, ip string) error {
	return nil
}
