package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type Dns2tcpdJsonResponse struct {
	Target    string `json:"target"`
	Key       string `json:"key"`
	UpdateKey string `json:"update_key"`
}

type Dns2tcpdResource struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

var dns2tcpdCmd = &cobra.Command{
	Use:   "dns2tcpd",
	Short: "Commands for managing dns2tcpd tunnels",
}

var createTunnelCmd = &cobra.Command{
	Use:   "create [ip] [port]",
	Short: "Create a new tunnel",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		ip := args[0]
		port := args[1]
		cliCreateTunnel(ip, port)
	},
}

var updateTunnelCmd = &cobra.Command{
	Use:   "update [updateKey] [resource1] [ip1] [port1] [resource2] [ip2] [port2]...",
	Short: "Update an existing tunnel with multiple resources",
	Run: func(cmd *cobra.Command, args []string) {
		updateKey := args[0]
		resources := args[1:]
		cliUpdateTunnel(updateKey, resources)
	},
}

var getConfigCmd = &cobra.Command{
	Use:   "get-config [updateKey] [resource] [local port]",
	Short: "Get the configuration for a specific resource",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		updateKey := args[0]
		resource := args[1]
		localPort := args[2]
		cliGetConfig(updateKey, resource, localPort)
	},
}

func initDns2tcpdCommands() {
	dns2tcpdCmd.AddCommand(createTunnelCmd, updateTunnelCmd, getConfigCmd)
	rootCmd.AddCommand(dns2tcpdCmd)
}

func cliGetConfig(updateKey, resource string, localPort string) {
	apiURL := "http://localhost:8080/v1/dns2tcpd/config"
	jsonData := map[string]string{
		"update_key": updateKey,
		"resource":   resource,
		"local_port": localPort,
	}
	jsonValue, _ := json.Marshal(jsonData)
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Fatalf("Error getting config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Failed to get config, status code: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	fmt.Printf("Config for resource %s:\n%s\n", resource, string(bodyBytes))
}

func cliCreateTunnel(ip, port string) {
	apiURL := fmt.Sprintf("http://localhost:8080/v1/dns2tcpd/create/%s/%s", ip, port)
	resp, err := http.Post(apiURL, "application/json", nil)
	if err != nil {
		log.Fatalf("Error creating tunnel: %v", err)
	}
	defer resp.Body.Close()

	var jsonResponse Dns2tcpdJsonResponse
	if err := json.NewDecoder(resp.Body).Decode(&jsonResponse); err != nil {
		log.Fatalf("Error decoding response: %v", err)
	}

	fmt.Printf("Tunnel created successfully:\nDomain: %s\nKey: %s\nUpdateKey: %s", jsonResponse.Target, jsonResponse.Key, jsonResponse.UpdateKey)

}

func cliUpdateTunnel(updateKey string, resourcesData []string) {
	apiURL := "http://localhost:8080/v1/dns2tcpd/update"

	var resources []Dns2tcpdResource
	for _, res := range resourcesData {
		parts := strings.Split(res, ",")
		if len(parts) != 3 {
			log.Fatalf("Invalid resource format: %s", res)
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			log.Fatalf("Invalid port number: %s", parts[2])
		}
		resources = append(resources, Dns2tcpdResource{
			Name: parts[0],
			IP:   parts[1],
			Port: port,
		})
	}

	updateData := struct {
		UpdateKey string             `json:"update_key"`
		Resources []Dns2tcpdResource `json:"resources"`
	}{
		UpdateKey: updateKey,
		Resources: resources,
	}

	jsonData, err := json.Marshal(updateData)
	if err != nil {
		log.Fatalf("Failed to marshal update data: %v", err)
	}

	request, err := http.NewRequest("PUT", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Failed to create HTTP request: %v", err)
	}
	request.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Fatalf("Failed to execute update request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		fmt.Println("Tunnel update successful.")
	} else {
		log.Fatalf("Tunnel update failed with status code: %d", response.StatusCode)
	}
}
