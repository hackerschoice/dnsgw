package main

import (
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"
)

func extractSubdomain(fullDomain string) string {
	fullDomain = strings.TrimSuffix(fullDomain, ".")

	domainToFind := "." + Config.DomainName

	pos := strings.Index(fullDomain, domainToFind)
	if pos == -1 {
		return ""
	}

	lastDotBeforeDomain := strings.LastIndex(fullDomain[:pos], ".")
	if lastDotBeforeDomain == -1 {
		return fullDomain
	}

	return fullDomain[lastDotBeforeDomain+1:]
}

func handleTunnel(r *dns.Msg, domain string) (*dns.Msg, error) {
	// NOTE: This will need some serious work to refactor to support multiple transports...
	// This function should probably just figure out what transport a tunnel dns entry is associated with
	// then call out to a dns2tcpd (or other transport) specific function
	var count int64
	err := db.Model(&Dns2TcpdTunnel{}).Where("domain = ?", domain).Count(&count).Error
	if err != nil {
		log.Errorf("Failed to query database for subdomain %s: %v", domain, err)
		return nil, fmt.Errorf("failed to validate subdomain %s: %v", domain, err)
	}
	if count == 0 {
		log.Debugf("Subdomain %s is not a valid tunnel", domain)
		return nil, fmt.Errorf("subdomain %s is not a valid tunnel", domain)
	}
	log.Debugf("Subdomain %s is a valid tunnel", domain)

	log.Debugf("Updating seen time for %s\n", domain)
	updateSubdomainState(domain, nil, false)

	state, ok := subdomains.Load(domain)
	if ok {
		log.Debugf("Subdomain entry for %s: %+v\n", domain, state)
		subdomainState := state.(*SubdomainState)
		subdomainState.Mutex.Lock()
		if subdomainState.Starting || (subdomainState.Cmd != nil && subdomainState.Cmd.Process != nil) {
			log.Debugf("Already running dns2tcpd for domain: %s", domain)
		} else {
			log.Debugf("Starting dns2tcpd for domain: %s", domain)
			subdomainState.Mutex.Unlock()
			startDns2tcpdForDomain(domain)
			subdomainState.Mutex.Lock()
		}
		subdomainState.Mutex.Unlock()
	} else {
		log.Errorf("Something has gone terribly wrong...")
		return nil, fmt.Errorf("failed to load subdomain state for domain: %s", domain)
	}

	localPort, err := getTunnelLocalPort(domain)
	if err != nil {
		log.Printf("Failed to get local port for tunnel: %v\n", err)
		return nil, fmt.Errorf("failed to get local port for tunnel: %v", err)
	}
	log.Debugf("Local port for tunnel: %d", localPort)

	addr := fmt.Sprintf("127.0.0.1:%d", localPort)

	c := new(dns.Client)

	log.Debugf("Forwarded DNS request: %+v", r)

	var out *dns.Msg

	for attempt := 0; attempt < 5; attempt++ {
		out, _, err = c.Exchange(r, addr)
		if err == nil {
			log.Debugf("Forwarded DNS query to %s\n", addr)
			break
		}
		log.Printf("Attempt %d: Failed to forward DNS query: %v\n", attempt+1, err)
		time.Sleep(time.Second * time.Duration(attempt+1))
	}

	if err != nil {
		log.Printf("Failed to forward DNS query: %v\n", err)
		return nil, fmt.Errorf("failed to forward DNS query: %v", err)
	}

	log.Debugf("Forwarded DNS answer: %+v", out)

	return out, nil
}

func forwardDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	c := new(dns.Client)
	in, _, err := c.Exchange(r, "1.1.1.1:53")
	if err != nil {
		log.Printf("Failed to forward DNS query: %v\n", err)
		return
	}
	w.WriteMsg(in)
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	log.Debugf("dns request: %s", r.Question[0].Name)

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			domain := strings.ToLower(q.Name)
			if !shouldHandle(q.Name) {
				forwardDNSQuery(w, r)
				return
			}

			subdomain := extractSubdomain(domain)
			log.Debugf("Subdomain: %s", subdomain)

			if subdomain == "ns."+Config.DomainName {
				log.Debugf("Handling nameserver request for subdomain: %s", domain)
				handleNameserver(w, r, domain)
			} else {
				log.Debugf("Handling tunnel request for subdomain: %s", subdomain)
				handled_r, err := handleTunnel(r, subdomain)
				if err != nil {
					log.Errorf("Error handling tunnel request: %v", err)
					return
				}
				if handled_r != nil {
					w.WriteMsg(handled_r)
					return
				}
			}
		}
	}
}

func handleNameserver(w dns.ResponseWriter, r *dns.Msg, subdomain string) {

}

func getTunnelLocalPort(domain string) (int, error) {
	var tunnel Dns2TcpdTunnel
	err := db.Where("domain = ?", domain).First(&tunnel).Error
	if err != nil {
		return 0, err
	}
	return tunnel.LocalPort, nil
}

func getIdentifierForDomain(domain string) (string, error) {
	var tunnel Dns2TcpdTunnel
	err := db.Select("identifier").Where("domain = ?", domain).First(&tunnel).Error
	if err != nil {
		return "", err
	}
	return tunnel.Identifier, nil
}

func shouldHandle(domain string) bool {
	return dns.IsSubDomain(Config.DomainName+".", domain)
}

func startDNS() *dns.Server {
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handleDNSRequest(w, r)
	})
	dnsServer := &dns.Server{Addr: ":53", Net: "udp"}
	log.Printf("Starting DNS server on %s\n", dnsServer.Addr)
	go func() {
		if err := dnsServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start DNS server: %v\n", err)
		}
	}()
	return dnsServer
}
