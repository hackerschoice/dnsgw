package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
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
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

var usedPorts = make(map[int]bool)

func serializeDns2tcpdConfig(config Dns2tcpdConfig) ([]byte, error) {
	configTemplate := `listen = {{.Listen}}
port = {{.Port}}
user = {{.User}}
key = {{.Key}}
chroot = {{.Chroot}}
domain = {{.Domain}}
identifier = {{.Identifier}}
resources = {{.ResourcesString}}`

	var resourcesParts []string
	for _, res := range config.Resources {
		resourcesParts = append(resourcesParts, fmt.Sprintf("%s:%s:%d", res.Name, res.IP, res.Port))
	}
	resourcesString := strings.Join(resourcesParts, ", ")

	tempConfig := struct {
		Dns2tcpdConfig
		ResourcesString string
	}{
		Dns2tcpdConfig:  config,
		ResourcesString: resourcesString,
	}

	tmpl, err := template.New("config").Parse(configTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, tempConfig); err != nil {
		return nil, fmt.Errorf("failed to execute config template: %v", err)
	}

	return buf.Bytes(), nil
}

func deserializeDns2tcpdConfig(configData []byte) (Dns2tcpdConfig, error) {
	log.Debug("Entering deserializeDns2tcpdConfig")
	var config Dns2tcpdConfig

	lines := strings.Split(string(configData), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		equalIndex := strings.Index(line, "=")
		if equalIndex == -1 {
			// NOTE: Technically lines after resources should be allowed to have no '='
			log.Errorf("Invalid line format, missing '=': %s", line)
			continue
		}
		key, value := strings.TrimSpace(line[:equalIndex]), strings.TrimSpace(line[equalIndex+1:])
		switch key {
		case "listen":
			config.Listen = value
		case "port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return Dns2tcpdConfig{}, fmt.Errorf("invalid port value: %v", err)
			}
			config.Port = port
		case "user":
			config.User = value
		case "key":
			config.Key = value
		case "chroot":
			config.Chroot = value
		case "domain":
			config.Domain = value
		case "identifier":
			config.Identifier = value
		case "resources":
			resources := strings.Split(value, ", ")
			for _, res := range resources {
				parts := strings.Split(res, ":")
				if len(parts) != 3 {
					return Dns2tcpdConfig{}, fmt.Errorf("invalid resource format: %s", res)
				}
				name, ip := parts[0], parts[1]
				port, err := strconv.Atoi(parts[2])
				if err != nil {
					return Dns2tcpdConfig{}, fmt.Errorf("invalid resource port value: %v", err)
				}
				config.Resources = append(config.Resources, Resource{Name: name, IP: ip, Port: port})
			}
		}
	}

	log.Debugf("Deserialized config: %+v", config)
	return config, nil
}

func getDns2tcpdConfig(c *gin.Context) {
	log.Debug("Entering getDns2tcpdConfig")
	var jsonBody struct {
		UpdateKey string `json:"update_key"`
		Resource  string `json:"resource"`
		LocalPort string `json:"local_port"`
	}
	if err := c.BindJSON(&jsonBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	if jsonBody.LocalPort == "" {
		jsonBody.LocalPort = "4433"
	}

	localPortInt, err := strconv.Atoi(jsonBody.LocalPort)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid local port"})
		return
	}
	if localPortInt <= 0 || localPortInt > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Local port out of range"})
		return
	}

	var identifier, domain string
	query := "SELECT identifier, domain FROM tunnels WHERE update_key = ? LIMIT 1"
	err = db.QueryRow(query, jsonBody.UpdateKey).Scan(&identifier, &domain)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Config not found"})
		} else {
			log.Errorf("Failed to query identifier and domain: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query identifier and domain"})
		}
		return
	}
	configFilePath := fmt.Sprintf("%s%s_%s_dns2tcpd.conf", Config.Dns2tcpdConfigPath, identifier, domain)

	configData, err := os.ReadFile(configFilePath)
	if err != nil {
		log.Errorf("Failed to read config file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read config file"})
		return
	}

	config, err := deserializeDns2tcpdConfig(configData)
	if err != nil {
		log.Errorf("Failed to deserialize config: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deserialize config"})
		return
	}

	var resource *Resource
	for _, res := range config.Resources {
		if res.Name == jsonBody.Resource {
			resource = &res
			break
		}
	}
	if resource == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Resource not found"})
		return
	}

	response := fmt.Sprintf("domain = %s\nresource = %s\nlocal_port = %s\ndebug_level = 1\nkey = %s\nserver = 127.0.0.1", config.Domain, resource.Name, jsonBody.LocalPort, config.Key)
	c.String(http.StatusOK, response)
}

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

func updateConfig(config Dns2tcpdConfig, newResources ...Resource) error {

	configFilePath := fmt.Sprintf("%s%s_%s_dns2tcpd.conf", Config.Dns2tcpdConfigPath, config.Identifier, config.Domain)

	log.Debugf("Updating config resources for tunnel identifier %s, config path: %s", config.Identifier, configFilePath)

	// Just to be sure..
	backupConfigFilePath := configFilePath + ".bak"

	srcFile, err := os.Open(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to open source config file %s: %w", configFilePath, err)
	}
	defer srcFile.Close()

	destFile, err := os.Create(backupConfigFilePath)
	if err != nil {
		return fmt.Errorf("failed to create backup config file %s: %w", backupConfigFilePath, err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy from source to backup config file: %w", err)
	}

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Recovered in updateConfig: %v", r)
			if restoreErr := os.Rename(backupConfigFilePath, configFilePath); restoreErr != nil {
				log.Errorf("failed to restore config from backup file %s: %v", backupConfigFilePath, restoreErr)
			}
		} else {
			if err := os.Remove(backupConfigFilePath); err != nil {
				log.Errorf("failed to delete backup config file %s: %v", backupConfigFilePath, err)
			}
		}
	}()

	fileContent, err := os.ReadFile(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", configFilePath, err)
	}

	existingConfig, err := deserializeDns2tcpdConfig(fileContent)
	if err != nil {
		return fmt.Errorf("failed to deserialize config: %w", err)
	}

	portChanged := false
	if existingConfig.Port != config.Port {
		log.Infof("Port change detected for tunnel identifier %s. Previous port: %d, New port: %d", config.Identifier, existingConfig.Port, config.Port)
		existingConfig.Port = config.Port
		portChanged = true
	}
	if len(newResources) > 0 {
		existingConfig.Resources = mergeResources(existingConfig.Resources, newResources)
	}

	updatedConfigContent, err := serializeDns2tcpdConfig(existingConfig)
	if err != nil {
		return fmt.Errorf("failed to serialize updated config: %w", err)
	}

	if err := os.WriteFile(configFilePath, updatedConfigContent, 0644); err != nil {
		return fmt.Errorf("failed to write updated config to file %s: %w", configFilePath, err)
	}

	if portChanged {
		updatePortSQL := `UPDATE tunnels SET local_port = ? WHERE identifier = ?`
		_, err = db.Exec(updatePortSQL, config.Port, config.Identifier)
		if err != nil {
			log.Errorf("Failed to update port in database for identifier %s: %v", config.Identifier, err)
			return fmt.Errorf("failed to update port in database for identifier %s: %v", config.Identifier, err)
		}
		log.Infof("Successfully updated port in database for identifier %s to %d", config.Identifier, config.Port)
	}

	log.Infof("Updated config resources for tunnel identifier %s", config.Identifier)
	return nil
}

func stopTunnelProcess(domain string) error {
	info, ok := subdomains.Load(domain)
	if !ok {
		log.Warnf("Subdomain %s not found in subdomains map, possibly not started yet", domain)
		return nil
	}

	subdomainState := info.(*SubdomainState)
	subdomainState.Mutex.Lock()
	defer subdomainState.Mutex.Unlock()

	if subdomainState.Cmd != nil && subdomainState.Cmd.Process != nil {
		err := subdomainState.Cmd.Process.Kill()
		if err != nil {
			log.Errorf("Failed to kill process for subdomain %s: %v", domain, err)
			return fmt.Errorf("failed to kill process for subdomain %s: %v", domain, err)
		}
		log.Infof("Killed process for subdomain %s", domain)
	}

	subdomains.Delete(domain)
	log.Infof("Removed subdomain %s from subdomains map", domain)

	return nil
}

func mergeResources(existing, new []Resource) []Resource {
	log.Debugf("Entering mergeResources")
	resourceMap := make(map[string]Resource)
	for _, r := range existing {
		resourceMap[r.Name] = r
	}
	for _, r := range new {
		resourceMap[r.Name] = r
	}

	merged := make([]Resource, 0, len(resourceMap))
	for _, r := range resourceMap {
		merged = append(merged, r)
	}
	log.Debugf("Merging resources: existing: %+v, new: %+v", existing, new)
	return merged

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
	configContent, err := serializeDns2tcpdConfig(config)
	if err != nil {
		return "", err
	}

	fileName := fmt.Sprintf("%s%s_%s_dns2tcpd.conf", Config.Dns2tcpdConfigPath, config.Identifier, config.Domain)

	err = os.WriteFile(fileName, []byte(configContent), 0644)
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

	configData, err := os.ReadFile(configFilePath)
	if err != nil {
		log.Printf("Failed to read config file %s: %v", configFilePath, err)
		return err
	}

	config, err := deserializeDns2tcpdConfig(configData)
	if err != nil {
		log.Printf("Failed to deserialize config data: %v", err)
		return err
	}

	port, err := findAvailablePort()
	if err != nil {
		log.Printf("Failed to find an open port: %v", err)
		return err
	}

	log.Debugf("Changing dns2tcpd port for domain %s to %d", domain, port)
	config.Port = port

	err = updateConfig(config)
	if err != nil {
		log.Printf("Failed to update config resources: %v", err)
		return err
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
