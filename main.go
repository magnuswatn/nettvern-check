package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/miekg/dns"
)

const (
	listenAddr     = ":3000"
	nettvernDomain = "nettvern-info.telenor.net."
)

// https://www.telenor.no/kundeservice/internett/sikkerhet/nettvern/
var dnsServers = []string{
	"148.122.16.253:53",
	"148.122.164.253:53",
}

func main() {
	slog.Info("Starting server", "listenAddr", listenAddr)
	http.HandleFunc("/nettvern_check/", handleRequest)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		slog.Warn("Got request without domain name", "client", r.RemoteAddr)
		http.Error(w, "Domain query parameter is required", http.StatusBadRequest)
		return
	}

	isBlocked, err := checkNettvern(domain)
	if err != nil {
		slog.Error("Failed to check domain", "domain", domain, "err", err, "client", r.RemoteAddr)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("Checked domain", "domain", domain, "isBlocked", isBlocked, "client", r.RemoteAddr)

	fmt.Fprintf(w, "%t", isBlocked)
}

func checkNettvern(domain string) (bool, error) {

	for _, server := range dnsServers {
		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
		r, _, err := c.Exchange(m, server)
		if err != nil {
			slog.Warn("Failed to query DNS server", "domain", domain, "server", server, "err", err)
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			if r.Rcode == dns.RcodeNameError { // NXDOMAIN
				slog.Debug("Got non-success code", "domain", domain, "server", server, "rcode", dns.RcodeToString[r.Rcode])
				return false, nil
			}
			didGoogleReturnSameError, err := verifyResponseWithGoogle(domain, r.Rcode)
			if err != nil {
				slog.Warn("Got non-success response from Telenor, and failed to verify against Google",
					"domain", domain, "server", server, "err", err, "googleErr", err)
				continue
			}
			if didGoogleReturnSameError {
				slog.Info("Got non-success code, but verified against Google",
					"domain", domain, "server", server, "rcode", dns.RcodeToString[r.Rcode])
				return false, nil
			}
			slog.Warn("Got non-success code", "domain", domain, "server", server, "rcode", dns.RcodeToString[r.Rcode])
			continue
		}

		for _, ans := range r.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				slog.Debug("CNAME answer", "domain", domain, "cnameTarget", cname.Target)
				return cname.Target == nettvernDomain, nil
			}
		}
		return false, nil
	}

	return false, fmt.Errorf("query failed against all DNS servers")
}

func verifyResponseWithGoogle(domain string, rcode int) (bool, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return false, err
	}
	return r.Rcode == rcode, nil
}
