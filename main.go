package main

import (
	"context"
	"database/sql"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

var db *sql.DB

func initDB() {
	// NOTE: ip, port, etc no longer really needed here, maybe we should store all the items in the config
	// in the database, so we can create them from scratch if we need to, but i think just keeping a persistent
	// config folder with each config is proabbly fine for now
	createTunnelsTable := `CREATE TABLE IF NOT EXISTS tunnels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		ip TEXT NOT NULL,
		port INTEGER NOT NULL,
		key TEXT NOT NULL,
		created_at TEXT NOT NULL,
		identifier TEXT NOT NULL,
		update_key TEXT NOT NULL,
		local_port INTEGER NOT NULL
	);`
	if _, err := db.Exec(createTunnelsTable); err != nil {
		log.Fatalf("Error creating tunnels table: %v", err)
	}

	createDNSTable := `CREATE TABLE IF NOT EXISTS nameserver (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		subdomain TEXT NOT NULL UNIQUE,
		ip TEXT NOT NULL,
		created_at TEXT NOT NULL
	);`
	if _, err := db.Exec(createDNSTable); err != nil {
		log.Fatalf("Error creating nameserver table: %v", err)
	}

}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./tunnels.db")
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	initDB()

	log.SetLevel(Config.LogLevel)

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

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatal("Failed to shutdown HTTP server:", err)
	}

	if err := dnsServer.ShutdownContext(ctx); err != nil {
		log.Fatal("Failed to shutdown DNS server:", err)
	}

	log.Println("Servers gracefully shutdown")
}
