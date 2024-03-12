package main

import (
	"log"
	"time"

	"gorm.io/gorm"
)

type Tunnel struct {
	gorm.Model
	Type       string `gorm:"index"`
	Identifier string `json:"identifier" gorm:"not null"`
	LocalPort  int
	CreatedAt  time.Time
}

func ListTunnelsByType(tunnelType string) {
	var tunnels []Tunnel

	// Query based on the Type field
	result := db.Where("type = ?", tunnelType).Find(&tunnels)

	if result.Error != nil {
		log.Printf("Error querying tunnels: %v", result.Error)
		return
	}

	for _, tunnel := range tunnels {
		log.Printf("Tunnel ID: %d, Type: %s, Identifier: %s", tunnel.ID, tunnel.Type, tunnel.Identifier)
	}
}
