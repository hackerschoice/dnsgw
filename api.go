package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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
}

type JsonResponse struct {
	Target string `json:"target"`
	Expiry int64  `json:"expiry"`
	Key    string `json:"key"`
}

func startAPI() *http.Server {

	initUsedPorts(Config.Dns2tcpdConfigPath)
	go startWatchdog(Config.WatchDogTimeout)

	router := gin.Default()
	// NOTE: Do this in a group so we can add more functionality later
	tcp := router.Group("/v1/tcp")
	{
		tcp.POST("/:ip/:port", createTunnel)
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
	log.Println("Creating tunnel...")

	ip := c.Param("ip")
	portStr := c.Param("port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("Error converting port: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid port"})
		return
	}

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

	tunnel := Tunnel{
		Domain:     domain,
		IP:         ip,
		Port:       port,
		CreatedAt:  time.Now().Format(time.RFC3339),
		Identifier: identifier,
		LocalPort:  localPort,
	}

	key, err := generateRandomKey(32)
	if err != nil {
		fmt.Printf("failed to generate random key: %v", err)
		return
	}

	config := Dns2tcpdConfig{
		Listen: "127.0.0.1",
		Port:   localPort,
		User:   "", // change to unpriv, nobody maybe
		Key:    key,
		Chroot: "", // also good for security
		Domain: domain,
		Resources: []Resource{
			{
				Name: "ssh",
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

	stmt, err := tx.Prepare("INSERT INTO tunnels (domain, ip, port, created_at, identifier, local_port) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		log.Printf("Error preparing statement: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare statement"})
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(tunnel.Domain, tunnel.IP, tunnel.Port, tunnel.CreatedAt, tunnel.Identifier, tunnel.LocalPort)
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
		Target: domain,
		Key:    key,
		Expiry: time.Now().Add(Config.WatchDogTimeout).Unix(),
	}

	c.JSON(http.StatusOK, jsonResponse)
}
