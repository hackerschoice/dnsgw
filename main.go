package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	log "github.com/sirupsen/logrus"
)

var db *gorm.DB
var domainService *DomainService

func initDB() {
	var err error
	if _, err := os.Stat(Config.TunnelDatabasePath); os.IsNotExist(err) {
		file, err := os.Create(Config.TunnelDatabasePath)
		if err != nil {
			log.Fatalf("Failed to create database file: %v", err)
		}
		file.Close()
	}

	db, err = gorm.Open(sqlite.Open(Config.TunnelDatabasePath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	err = db.AutoMigrate(&Dns2TcpdTunnel{}, &NameServer{})
	if err != nil {
		log.Fatalf("Error migrating database: %v", err)
	}
}

func main() {
	log.SetLevel(Config.LogLevel)

	initDB()

	// For the domain service
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	domainService = NewDomainService(ctx, 15*time.Minute, 1*time.Hour)

	httpServer := startAPI()

	configPath := Config.Dns2tcpdConfigPath
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("Config path %s does not exist", configPath)
	}

	tmpFilePath := filepath.Join(configPath, ".tmp-write-test")
	file, err := os.OpenFile(tmpFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Fatalf("Config path %s is not writable", configPath)
	}
	file.Close()
	os.Remove(tmpFilePath)
	log.Infof("Config path %s is valid and writable", configPath)

	dnsServer := startDNS()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Fatal("Failed to shutdown HTTP server:", err)
	}

	if err := dnsServer.ShutdownContext(shutdownCtx); err != nil {
		log.Fatal("Failed to shutdown DNS server:", err)
	}

	log.Println("Servers gracefully shutdown")
}
