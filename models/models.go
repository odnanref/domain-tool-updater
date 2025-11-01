package models

import "time"

// DomainInfo represents the structure you provided
type DomainInfo struct {
	Name        string
	Registrar   string
	State       string
	Tier        string
	TransferTo  string
	LastCheck   time.Time
	Spf         string
	Dmarc       string
	Nameservers string
	Status      bool
	Whois		string
}