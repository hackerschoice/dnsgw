package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type Dns2tcpdConfig struct {
	Listen     string
	Port       int
	User       string
	Key        string
	Chroot     string
	Domain     string
	Resources  []Resource
	Identifier string
}

type Resource struct {
	Name string
	IP   string
	Port int
}

var usedPorts = make(map[int]bool)

func initUsedPorts(configDir string) {
	err := filepath.Walk(configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".conf" {
			port, err := extractPortFromConfig(path)
			if err != nil {
				log.Printf("Failed to extract port from config file %s: %v", path, err)
				return nil
			}
			usedPorts[port] = true
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Failed to walk through config directory %s: %v", configDir, err)
	}

	log.Printf("Initialized used ports from existing configs. Total ports: %d", len(usedPorts))
}

func extractPortFromConfig(configFilePath string) (int, error) {
	content, err := os.ReadFile(configFilePath)
	if err != nil {
		log.Printf("Failed to read config file: %v", err)
		return 0, err
	}

	portRegex := regexp.MustCompile(`port = (\d+)`)
	matches := portRegex.FindSubmatch(content)
	if len(matches) > 1 {
		port, err := strconv.Atoi(string(matches[1]))
		if err == nil {
			return port, nil
		}
	}
	return 0, err
}

func findAvailablePort() (int, error) {
	for port := 1025; port <= 65535; port++ {
		if _, used := usedPorts[port]; !used {
			listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
			if err != nil {
				continue
			}
			listener.Close()

			usedPorts[port] = true
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available ports found")
}

func generateRandomKey(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid key length: %d", length)
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	var bytes = make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}

	return string(bytes), nil
}

func createDns2tcpdConfigFile(config Dns2tcpdConfig) (string, error) {
	var resourcesLines []string
	for _, resource := range config.Resources {
		resourcesLines = append(resourcesLines, fmt.Sprintf("%s:%s:%d", resource.Name, resource.IP, resource.Port))
	}
	resourcesStr := strings.Join(resourcesLines, ",\n\t\t")

	configContent := fmt.Sprintf(`listen = %s
port = %d
user = %s
key = %s
chroot = %s
domain = %s
resources = %s
`, config.Listen, config.Port, config.User, config.Key, config.Chroot, config.Domain, resourcesStr)

	fileName := fmt.Sprintf("%s%s_%s_dns2tcpd.conf", Config.Dns2tcpdConfigPath, config.Identifier, config.Domain)

	err := ioutil.WriteFile(fileName, []byte(configContent), 0644)
	if err != nil {
		return "", err
	}

	return fileName, nil
}

func startDns2tcpdForDomain(db *sql.DB, domain string) error {
	identifier, err := getIdentifierForDomain(db, domain)
	if err != nil {
		log.Printf("Failed to get identifier for domain %s: %v", domain, err)
		return err
	}

	configFilePath := fmt.Sprintf("%s%s_%s_dns2tcpd.conf", Config.Dns2tcpdConfigPath, identifier, domain)

	port, err := extractPortFromConfig(configFilePath)
	if err != nil {
		log.Printf("Failed to extract port from config file %s: %v", configFilePath, err)
		return nil
	}

	err = startDns2tcpd(domain, configFilePath)
	if err != nil {
		log.Printf("Failed to start dns2tcpd for domain %s: %v", domain, err)
		return err
	}

	log.Debugf("dns2tcpd started for %s, beginning reachability check at port %d", domain, port)

	conn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)
	if err != nil {
		log.Printf("Reachability check failed for domain: %s, port %d: %v", domain, port, err)
		return err
	}
	defer conn.Close()
	log.Debugf("Reachability check succeeded for port %d", port)

	return nil
}

func startDns2tcpd(domain string, configFilePath string) error {
	cmd := exec.Command("/usr/local/bin/dns2tcpd", "-F", "-d", "1", "-f", configFilePath)
	log.Debugf("Starting /usr/local/bin/dns2tcpd -F -d 1 -f %s", configFilePath)

	if err := cmd.Start(); err != nil {
		log.Printf("Failed to start dns2tcpd: %v", err)
		return err
	}

	log.Debugf("dns2tcpd successfully started for domain %s", domain)

	updateSubdomainState(domain, cmd, true)
	newState, _ := subdomains.Load(domain)
	log.Debugf("Before subdomain state: %+v", newState)
	updateSubdomainState(domain, cmd, false)
	newState, _ = subdomains.Load(domain)
	log.Debugf("After subdomain state: %+v", newState)

	log.Debugf("dns2tcpd started for domain %s", domain)
	return nil
}
