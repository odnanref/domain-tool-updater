// updater.go
package main

import (
	"domain-tool-updater/database"
	"domain-tool-updater/dnsquery"
	"domain-tool-updater/events"
	"domain-tool-updater/models"
	"domain-tool-updater/subscribers"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

func joinMapByColon(m map[string]string) string {
	var pairs []string
	for key, value := range m {
		pairs = append(pairs, key+":"+value)
	}
	return strings.Join(pairs, ", ")
}

func main() {

	// Initialize Observer and register SMTP subscriber
	Observer := Observer{}
	Observer.RegisterSubscriber(subscribers.NewSmtpSubscriber())

	fmt.Println("Started Updater...")

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		dbUser, dbPassword, dbHost, dbName)

	database.Initialize(dsn)
	defer database.Close()

	domains, err := database.GetDomainInfoAll()
	if err != nil {
		log.Printf("ERROR: Rows iteration error: %v", err)
		panic("ERROR Getting all domains")
	}

	for _, domain := range domains {
		domain_stored, StorageErr := database.GetDomainInfoHistory(domain.Name)

		log.Println("Domain being checked: ", domain.Name)
		nsRecords, err := dnsquery.GetNSRecords(domain.Name)
		nsRecordcomma := ""
		if err != nil {
			log.Println("Domain NS Record not found ", domain.Name)
		} else {
			for _, ns := range nsRecords {
				nsRecordcomma = nsRecordcomma + ", " + ns
			}
		}
		database.UpdateNS(domain.Name, nsRecordcomma)

		dmarcRecord, err := dnsquery.GetDMARCRecord(domain.Name)
		if err != nil {
			log.Println("Domain DMARC Record not found ", domain.Name)
		}
		database.UpdateDMARC(domain.Name, dmarcRecord)

		spfRecord, err := dnsquery.GetSPFRecord(domain.Name)
		if err != nil {
			log.Println("Domain SPF Record not found ", domain.Name)
		}
		database.UpdateSPF(domain.Name, spfRecord)

		domainRec, err := database.GetDomainInfo(domain.Name)
		if err != nil {
			log.Println("Error geting info for domain Name:", domain.Name)
		}

		mapOfDates := dnsquery.GetAllDatesFromWhois(domain.Name)
		for _, valor := range mapOfDates {
			fmt.Println("Key Value:", valor)
		}
		for chave, valor := range mapOfDates {
			fmt.Printf("Key %s Value: %s", chave, valor)
		}
		// Whois information
		whois := ""
		if len(mapOfDates) > 0 {
			whois = joinMapByColon(mapOfDates)
			database.UpdateWhois(domain.Name, whois)
		}

		newDomainInfo := models.DomainInfo{
			Name:        domainRec.Name,
			Registrar:   domainRec.Registrar,
			State:       domainRec.State,
			Tier:        domainRec.Tier,
			TransferTo:  domainRec.TransferTo,
			LastCheck:   time.Now(),
			Dmarc:       dmarcRecord,
			Spf:         spfRecord,
			Nameservers: nsRecordcomma,
			Status:      true,
			Whois:       whois,
		}

		// Compare with stored data and create events for changes
		if StorageErr == nil {
			hasChanges := false

			if dmarcRecord != domain_stored.Dmarc {
				event := events.Event{
					EventType:      events.EventTypeDmarc,
					EventAction:    events.EventActionChange,
					ExecuteTime:    time.Now(),
					DomainInfo:     newDomainInfo,
					DomainInfoPrev: *domain_stored,
				}
				Observer.Notify(event)
				log.Printf("DMARC change detected for domain %s. Old: %s, New: %s", domain.Name, domain_stored.Dmarc, dmarcRecord)
				// Here you would trigger your alert/notification system with the event
				hasChanges = true
			}

			if spfRecord != domain_stored.Spf {
				event := events.Event{
					EventType:      events.EventTypeSpf,
					EventAction:    events.EventActionChange,
					ExecuteTime:    time.Now(),
					DomainInfo:     newDomainInfo,
					DomainInfoPrev: *domain_stored,
				}
				Observer.Notify(event)
				log.Printf("SPF change detected for domain %s. Old: %s, New: %s", domain.Name, domain_stored.Spf, spfRecord)
				// Here you would trigger your alert/notification system with the event
				hasChanges = true
			}

			if nsRecordcomma != domain_stored.Nameservers {
				event := events.Event{
					EventType:      events.EventTypeNameservers,
					EventAction:    events.EventActionChange,
					ExecuteTime:    time.Now(),
					DomainInfo:     newDomainInfo,
					DomainInfoPrev: *domain_stored,
				}
				Observer.Notify(event)

				log.Printf("Nameservers change detected for domain %s. Old: %s, New: %s", domain.Name, domain_stored.Nameservers, nsRecordcomma)
				// Here you would trigger your alert/notification system with the event
				hasChanges = true
			}

			// Only insert into history if there were actual changes
			if hasChanges {
				err_insert := database.InsertDomainHistory(newDomainInfo)
				if err_insert != nil {
					log.Printf("Error trying to insert history for domain %s: %v", domain.Name, err_insert)
				}
			}
		} else {
			// If there's no stored history, this is the first entry
			err_insert := database.InsertDomainHistory(newDomainInfo)
			if err_insert != nil {
				log.Printf("Error trying to insert first history for domain %s: %v", domain.Name, err_insert)
			}
		}
	}

}
