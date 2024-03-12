package main

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type IodineTunnel struct {
	Tunnel
	Domain string
	IP     string
}

func createIodineTunnel(c *gin.Context) {
	if !validateAccessMode(c) {
		return
	}

	log.Debug("Creating iodine tunnel...")

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

}
