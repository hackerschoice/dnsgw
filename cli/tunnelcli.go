package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tunnelcli",
	Short: "TunnelCLI is a simple command line tool to manage tunnels",
}

func getApiBaseUrl() string {
	defaultBaseUrl := "http://localhost:8080"
	baseUrl := os.Getenv("TUNNELCLI_API_BASE_URL")
	if baseUrl == "" {
		baseUrl = defaultBaseUrl
	}
	return baseUrl
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	initDns2tcpdCommands()
}
