package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"net"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type DomainEntry struct {
	ID          uint      `gorm:"primaryKey"`
	Domain      string    `gorm:"unique;not null"`
	LastChecked time.Time `gorm:"not null"`
	IsValid     bool      `gorm:"not null;default:true"`
}

type NameServer struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Subdomain string    `json:"subdomain" gorm:"unique;not null"`
	IP        string    `json:"ip" gorm:"not null"`
	CreatedAt time.Time `json:"created_at" gorm:"type:timestamp;not null"`
}

type JsonResponse struct {
	Target    string `json:"target"`
	Key       string `json:"key"`
	UpdateKey string `json:"update_key"`
}

var tunnelUpdateMutexes = make(map[string]*sync.Mutex)
var tunnelUpdateMapMutex sync.Mutex

func startAPI() *http.Server {

	go startWatchdog(Config.WatchDogTimeout)

	router := gin.Default()
	tcp := router.Group("/v1/dns2tcpd")
	{
		tcp.POST("/create/:ip/:port", createTunnel)
		tcp.PUT("/update", updateTunnel)
		tcp.POST("/config", getDns2tcpdConfig)
	}

	iodine := router.Group("/v1/iodine")
	{
		iodine.POST("/create/:ip/:port", createIodineTunnel)
	}

	ns := router.Group("/v1/ns")
	{
		ns.POST("/:ip", createNsEntry)
	}

	add := router.Group("/v1/add")
	{
		add.POST("/:domain", addDomain)
	}

	httpServer := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	return httpServer

}

func validateAccessMode(c *gin.Context) bool {
	mode := Config.AccessMode.Mode()
	switch mode {
	case "Public":
	case "TokenRequired":
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			return false
		}
		// TODO: Process tokens
	case "PreSharedKey":
		psk := c.GetHeader("X-PreShared-Key")
		if psk == "" || psk != (Config.AccessMode.(PreSharedKeyMode)).Key {
			log.Debugf("Incorrect PSK provided")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing Pre-Shared Key"})
			return false
		}
		log.Debugf("Correct PSK provided, continuing")
	default:
		log.Fatalf("Unknown access mode: %s", mode)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
		return false
	}
	return true
}

func validateCIDRBlacklist(ip string, c *gin.Context) bool {
	for _, cidr := range Config.BlacklistedCIDRs {
		_, blacklistedNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Errorf("Failed to parse blacklisted CIDR %s: %v", cidr, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to parse blacklisted CIDR: %v", err)})
			return false
		}
		if blacklistedNet.Contains(net.ParseIP(ip)) {
			log.Errorf("Resource IP %s is in a blacklisted CIDR range %s", ip, cidr)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Resource IP %s is in a blacklisted CIDR range", ip)})
			return false
		}
	}
	log.Debug("All resources validated against blacklisted CIDRs")
	return true
}

func addDomain(c *gin.Context) {
	domain := c.Param("domain")

	err := domainService.AddDomainEntry(domain)
	if err != nil {
		log.Errorf("Failed to add domain: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Domain added successfully", "domain": domain})
}

func updateTunnel(c *gin.Context) {
	log.Debug("Starting updateTunnel function")
	type updateRequest struct {
		UpdateKey string     `json:"update_key"`
		Resources []Resource `json:"resources"`
	}

	var req updateRequest
	if err := c.BindJSON(&req); err != nil {
		log.Debugf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	log.Debug("Successfully bound JSON to updateRequest struct")

	var tunnel Dns2TcpdTunnel
	err := db.Where("update_key = ?", req.UpdateKey).First(&tunnel).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Debug("Tunnel not found with provided update_key")
			c.JSON(http.StatusNotFound, gin.H{"error": "Tunnel not found"})
		} else {
			log.Errorf("Failed to query tunnel: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query tunnel"})
		}
		return
	}
	log.Debug("Successfully queried tunnel from database")

	tunnelUpdateMapMutex.Lock()
	log.Debug("Acquired tunnelUpdateMapMutex lock")
	mutex, exists := tunnelUpdateMutexes[tunnel.Identifier]
	if !exists {
		mutex = &sync.Mutex{}
		tunnelUpdateMutexes[tunnel.Identifier] = mutex
		log.Debugf("Created new mutex for tunnel identifier: %s", tunnel.Identifier)
	}
	tunnelUpdateMapMutex.Unlock()
	log.Debug("Released tunnelUpdateMapMutex lock")

	mutex.Lock()
	log.Debugf("Acquired mutex lock for tunnel identifier: %s", tunnel.Identifier)
	defer func() {
		mutex.Unlock()
		log.Debugf("Released mutex lock for tunnel identifier: %s", tunnel.Identifier)
	}()

	configFilePath := fmt.Sprintf("%s%s_%s_dns2tcpd.conf", Config.Dns2tcpdConfigPath, tunnel.Identifier, tunnel.Domain)
	log.Debugf("Reading config file from path: %s", configFilePath)

	configData, err := os.ReadFile(configFilePath)
	if err != nil {
		log.Errorf("Failed to read config file %s: %v", configFilePath, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to read config file: %v", err)})
		return
	}

	var config Dns2tcpdConfig
	if config, err = deserializeDns2tcpdConfig(configData); err != nil {
		log.Errorf("Failed to deserialize config data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to deserialize config: %v", err)})
		return
	}
	log.Debug("Successfully deserialized config from disk")

	for _, resource := range req.Resources {
		for _, cidr := range Config.BlacklistedCIDRs {
			_, blacklistedNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Errorf("Failed to parse blacklisted CIDR %s: %v", cidr, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to parse blacklisted CIDR: %v", err)})
				return
			}
			if blacklistedNet.Contains(net.ParseIP(resource.IP)) {
				log.Errorf("Resource IP %s is in a blacklisted CIDR range %s", resource.IP, cidr)
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Resource IP %s is in a blacklisted CIDR range", resource.IP)})
				return
			}
		}
	}
	log.Debug("All resources validated against blacklisted CIDRs")

	if err := updateConfig(config, req.Resources...); err != nil {
		log.Errorf("Failed to update config resources: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update config resources"})
		return
	}
	log.Debug("Successfully updated config resources")

	_, subdomainExists := subdomains.Load(tunnel.Domain)
	var subdomainSeen bool
	if subdomainExists {
		subdomainSeen = true
	}

	if err := stopTunnelProcess(tunnel.Domain); err != nil {
		log.Errorf("Failed to stop existing tunnel process for domain %s: %v", tunnel.Domain, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to stop existing tunnel process"})
		return
	}
	log.Debugf("Successfully stopped tunnel process for domain: %s", tunnel.Domain)

	if subdomainSeen {
		if err := startDns2tcpdForDomain(tunnel.Domain); err != nil {
			log.Errorf("Failed to start new tunnel process for domain %s: %v", tunnel.Domain, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start new tunnel process"})
			return
		}
		log.Debugf("Successfully started new tunnel process for domain: %s", tunnel.Domain)
	} else {
		log.Debugf("Subdomain %s has not been seen before, skipping tunnel start.", tunnel.Domain)
	}

	status := "waiting"
	if subdomainSeen {
		status = "restarting"
	}
	c.JSON(http.StatusOK, gin.H{"message": "Config updated successfully", "status": status})
	log.Debug("updateTunnel function completed successfully")
}

func generateDomainName() string {
	log.Println("Generating domain name...")

	const letters = "abcdefghijklmnopqrstuvwxyz"
	const digits = "0123456789"
	const charset = letters + digits

	var existingDomains []string
	if err := db.Model(&Dns2TcpdTunnel{}).Order("domain ASC").Pluck("domain", &existingDomains).Error; err != nil {
		log.Printf("Error querying existing domains: %v\n", err)
		return ""
	}

	rand.Seed(time.Now().UnixNano())
	domainIndex := rand.Intn(len(Config.DomainNames))
	baseDomain := "." + Config.DomainNames[domainIndex]

	sequence := "a"
	for _, domain := range existingDomains {
		if domain == sequence+baseDomain {
			sequence = incrementSequence(sequence, charset)
		} else {
			break
		}
	}

	// ns. is special
	if sequence == "ns" {
		sequence = incrementSequence(sequence, charset)
	}

	return sequence + baseDomain
}

func incrementSequence(s, charset string) string {
	if s == "" {
		return "a"
	}

	lastChar := s[len(s)-1]
	if lastChar == '9' {
		return incrementSequence(s[:len(s)-1], charset) + "a"
	} else {
		pos := strings.Index(charset, string(lastChar))
		if pos == len(charset)-1 { // If 'z', reset to '0' and increment previous
			return incrementSequence(s[:len(s)-1], charset) + "0"
		}
		// Increment the last character
		return s[:len(s)-1] + string(charset[pos+1])
	}
}

func createTunnel(c *gin.Context) {
	if !validateAccessMode(c) {
		return
	}

	log.Println("Creating tunnel...")

	ip := c.Param("ip")
	if !validateCIDRBlacklist(ip, c) {
		return
	}

	portStr := c.Param("port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("Error converting port: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid port"})
		return
	}

	identifier := uuid.New().String()
	log.Printf("Generating domain name for IP: %s, Port: %d with Identifier: %s\n", ip, port, identifier)
	domain := generateDomainName()

	log.Printf("Generated domain: %s\n", domain)

	localPort, err := findAvailablePort()
	if err != nil {
		log.Printf("Error finding available port: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find available port"})
		return
	}
	log.Debugf("Available port found: %d\n", localPort)

	key, err := generateRandomKey(32)
	if err != nil {
		fmt.Printf("failed to generate random key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tunnel key"})
		return
	}

	updateKey, err := generateRandomKey(32)
	if err != nil {
		log.Printf("failed to generate update key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate update key"})
		return
	}

	tunnel := Dns2TcpdTunnel{
		Domain:     domain,
		IP:         ip,
		Port:       port,
		CreatedAt:  time.Now(),
		Identifier: identifier,
		LocalPort:  localPort,
		Key:        key,
		UpdateKey:  updateKey,
	}

	config := Dns2tcpdConfig{
		// maybe we'll change this to use the entire loopback range, but i think we wont have more than
		// 64k connections actively being used
		Listen: "127.0.0.1",
		Port:   localPort,
		User:   "", // change to unpriv, nobody maybe
		Key:    key,
		Chroot: "", // also good for security
		Domain: domain,
		Resources: []Resource{
			{
				Name: "main",
				IP:   ip,
				Port: port,
			},
		},
		Identifier: identifier,
	}

	_, err = createDns2tcpdConfigFile(config)
	if err != nil {
		log.Fatalf("Can't create config file: %v", err)
		return
	}

	tx := db.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to begin transaction"})
		return
	}

	if err := tx.Create(&tunnel).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute statement"})
		return
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	if c.Query("plain") == "true" {
		c.String(http.StatusOK, fmt.Sprintf("%s,%s,%d", domain, key, time.Now().Add(Config.WatchDogTimeout).Unix()))
		return
	}

	jsonResponse := JsonResponse{
		Target:    domain,
		Key:       key,
		UpdateKey: updateKey,
	}

	c.JSON(http.StatusOK, jsonResponse)
}
