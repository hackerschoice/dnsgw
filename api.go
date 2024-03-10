package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"net"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type Tunnel struct {
	ID         int    `json:"id"`
	Domain     string `json:"domain"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	CreatedAt  string `json:"created_at"`
	Identifier string `json:"identifier"`
	LocalPort  int    `json:"local_port"`
	Key        string `json:"key"`
	UpdateKey  string `json:"update_key"`
}

type JsonResponse struct {
	Target    string `json:"target"`
	Key       string `json:"key"`
	UpdateKey string `json:"update_key"`
}

var tunnelUpdateMutexes = make(map[string]*sync.Mutex)
var tunnelUpdateMapMutex sync.Mutex

func startAPI() *http.Server {

	initUsedPorts(Config.Dns2tcpdConfigPath)
	go startWatchdog(Config.WatchDogTimeout)

	router := gin.Default()
	tcp := router.Group("/v1/dns2tcpd")
	{
		tcp.POST("/create/:ip/:port", createTunnel)
		tcp.PUT("/update", updateTunnel)
		tcp.POST("/config", getDns2tcpdConfig)
	}

	ns := router.Group("/v1/ns")
	{
		ns.POST("/:ip", createNsEntry)
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

	var tunnel Tunnel
	query := "SELECT id, domain, ip, port, created_at, identifier, key, update_key, local_port FROM tunnels WHERE update_key = ? LIMIT 1"
	log.Debugf("Executing query: %s", query)
	err := db.QueryRow(query, req.UpdateKey).Scan(&tunnel.ID, &tunnel.Domain, &tunnel.IP, &tunnel.Port, &tunnel.CreatedAt, &tunnel.Identifier, &tunnel.Key, &tunnel.UpdateKey, &tunnel.LocalPort)
	if err != nil {
		if err == sql.ErrNoRows {
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
		if err := startDns2tcpdForDomain(db, tunnel.Domain); err != nil {
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

func generateDomainName(db *sql.DB) string {
	log.Println("Generating domain name...")

	const letters = "abcdefghijklmnopqrstuvwxyz"
	const digits = "0123456789"
	const charset = letters + digits

	rows, err := db.Query("SELECT domain FROM tunnels ORDER BY domain ASC")
	if err != nil {
		log.Printf("Error querying existing domains: %v\n", err)
		return ""
	}
	defer rows.Close()

	existingDomains := make([]string, 0)
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			log.Printf("Error scanning domain: %v\n", err)
			continue
		}
		existingDomains = append(existingDomains, domain)
	}

	baseDomain := "." + Config.DomainName
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

	mode := Config.AccessMode.Mode()
	switch mode {
	case "Public":
	case "TokenRequired":
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			return
		}
		// TODO: Process tokens
	case "PreSharedKey":
		psk := c.GetHeader("X-PreShared-Key")
		if psk == "" || psk != (Config.AccessMode.(PreSharedKeyMode)).Key {
			log.Debugf("Incorrect PSK provided")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing Pre-Shared Key"})
			return
		}
		log.Debugf("Correct PSK provided, continuing")
	default:
		log.Fatalf("Unknown access mode: %s", mode)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
		return
	}

	log.Println("Creating tunnel...")

	ip := c.Param("ip")
	portStr := c.Param("port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("Error converting port: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid port"})
		return
	}

	for _, cidr := range Config.BlacklistedCIDRs {
		_, blacklistedNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Errorf("Failed to parse blacklisted CIDR %s: %v", cidr, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to parse blacklisted CIDR: %v", err)})
			return
		}
		if blacklistedNet.Contains(net.ParseIP(ip)) {
			log.Errorf("Resource IP %s is in a blacklisted CIDR range %s", ip, cidr)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Resource IP %s is in a blacklisted CIDR range", ip)})
			return
		}
	}
	log.Debug("All resources validated against blacklisted CIDRs")

	identifier := uuid.New().String()
	log.Printf("Generating domain name for IP: %s, Port: %d with Identifier: %s\n", ip, port, identifier)
	domain := generateDomainName(db)

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

	tunnel := Tunnel{
		Domain:     domain,
		IP:         ip,
		Port:       port,
		CreatedAt:  time.Now().Format(time.RFC3339),
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

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to begin transaction"})
		return
	}

	stmt, err := tx.Prepare("INSERT INTO tunnels (domain, ip, port, created_at, identifier, local_port, key, update_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		log.Printf("Error preparing statement: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare statement"})
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(tunnel.Domain, tunnel.IP, tunnel.Port, tunnel.CreatedAt, tunnel.Identifier, tunnel.LocalPort, tunnel.Key, tunnel.UpdateKey)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute statement"})
		return
	}

	if err := tx.Commit(); err != nil {
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
