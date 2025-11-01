package database

import (
	"database/sql"
	"domain-tool-updater/models"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

var db *sql.DB

// Initialize initializes the database connection
func Initialize(dataSourceName string) {
	var err error
	db, err = sql.Open("postgres", dataSourceName)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Database connected successfully!")
}

// Close closes the database connection
func Close() {
	if db != nil {
		db.Close()
	}
}

func GetDomainInfo(domainName string) (*models.DomainInfo, error) {
	query := "SELECT name, registrar, state, tier, transfer_to, last_check, spf, dmarc, nameservers, status, whois FROM domain_info WHERE name = $1"
	var domain models.DomainInfo
	err := db.QueryRow(query, domainName).Scan(
		&domain.Name,
		&domain.Registrar,
		&domain.State,
		&domain.Tier,
		&domain.TransferTo,
		&domain.LastCheck,
		&domain.Spf,
		&domain.Dmarc,
		&domain.Nameservers,
		&domain.Status,
		&domain.Whois,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no domain found with name: %s", domainName)
		}
		return nil, err
	}

	return &domain, nil
}

func GetDomainInfoAll() ([]models.DomainInfo, error) {
	query := "SELECT name, registrar, state, tier, transfer_to, last_check, spf, dmarc, nameservers, status, whois FROM domain_info WHERE status = true"
	rows, err := db.Query(query)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var domains []models.DomainInfo
	for rows.Next() {
		var domain models.DomainInfo
		if err := rows.Scan(
			&domain.Name,
			&domain.Registrar,
			&domain.State,
			&domain.Tier,
			&domain.TransferTo,
			&domain.LastCheck,
			&domain.Spf,
			&domain.Dmarc,
			&domain.Nameservers,
			&domain.Status,
			&domain.Whois,
		); err != nil {

			return nil, err
		}

		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

func GetDomainInfoHistory(domainName string) (*models.DomainInfo, error) {
	query := "SELECT name, registrar, state, tier, transfer_to, last_check, spf, dmarc, nameservers, status, whois FROM domain_info_history WHERE name = $1"
	var domain models.DomainInfo
	err := db.QueryRow(query, domainName).Scan(
		&domain.Name,
		&domain.Registrar,
		&domain.State,
		&domain.Tier,
		&domain.TransferTo,
		&domain.LastCheck,
		&domain.Spf,
		&domain.Dmarc,
		&domain.Nameservers,
		&domain.Status,
		&domain.Whois,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no domain found with name: %s", domainName)
		}
		return nil, err
	}

	return &domain, nil
}

func UpdateSPF(domainName string, spfRecord string) error {
	query := "UPDATE domain_info SET spf = $1, last_check=NOW() WHERE name = $2"
	_, err := db.Exec(query, spfRecord, domainName)
	return err
}

func UpdateDMARC(domainName string, DmarcRecord string) error {
	query := "UPDATE domain_info SET dmarc = $1, last_check=NOW() WHERE name = $2"
	_, err := db.Exec(query, DmarcRecord, domainName)
	return err
}

func UpdateNS(domainName string, nsRecord string) error {
	query := "UPDATE domain_info SET nameservers = $1, last_check=NOW() WHERE name = $2"
	_, err := db.Exec(query, nsRecord, domainName)
	return err
}

func UpdateWhois(domainName string, whois string) error {
	query := "UPDATE domain_info SET whois = $1, last_check=NOW() WHERE name = $2"
	_, err := db.Exec(query, whois, domainName)
	return err
}

func InsertDomainHistory(domain models.DomainInfo) error {
	_, err := db.Exec("INSERT INTO domain_info_history (name, registrar, state, tier, transfer_to, last_check, spf, dmarc, nameservers, status, whois) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
		domain.Name, domain.Registrar, domain.State, domain.Tier, domain.TransferTo, domain.LastCheck, domain.Spf, domain.Dmarc, domain.Nameservers, true, domain.Whois)
	return err
}
