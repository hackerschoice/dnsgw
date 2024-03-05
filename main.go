package main

import (
	"context"
	"database/sql"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

var db *sql.DB

func initDB() {
	createTunnelsTable := `CREATE TABLE IF NOT EXISTS tunnels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		ip TEXT NOT NULL,
		port INTEGER NOT NULL,
		created_at TEXT NOT NULL,
		identifier TEXT NOT NULL,
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

	log.SetLevel(log.DebugLevel)

	httpServer := startAPI()

	configPath := Config.Dns2tcpdConfigPath
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("Config path %s does not exist", configPath)
	}

	file, err := os.OpenFile(configPath, os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Config path %s is not writable", configPath)
	}
	file.Close()
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
