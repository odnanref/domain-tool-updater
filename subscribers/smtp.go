package subscribers

import (
	"domain-tool-updater/events"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"strconv"
)

type SmtpSubscriber struct {
	smtpHost     string
	smtpPort     int
	smtpUser     string
	smtpPassword string
	fromEmail    string
	toEmail      string
}

func (s *SmtpSubscriber) Update(event events.Event) {
	// Implementation of the Update method to handle events
	switch event.GetEventType() {
	case events.EventTypeNameservers:
		domainInfo := event.GetDomainInfo()
		domainInfoPrev := event.DomainInfoPrev
		s.OnDomainChange(domainInfo.Name, domainInfoPrev.Nameservers, domainInfo.Nameservers)
	case events.EventTypeDmarc:
		domainInfo := event.GetDomainInfo()
		domainInfoPrev := event.DomainInfoPrev
		s.OnDomainChange(domainInfo.Name, domainInfoPrev.Dmarc, domainInfo.Dmarc)
	case events.EventTypeSpf:
		domainInfo := event.GetDomainInfo()
		domainInfoPrev := event.DomainInfoPrev
		s.OnDomainChange(domainInfo.Name, domainInfoPrev.Spf, domainInfo.Spf)
	}
}

func NewSmtpSubscriber() *SmtpSubscriber {

	// Initialize SMTP subscriber
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	fromEmail := os.Getenv("FROM_EMAIL")
	toEmail := os.Getenv("TO_EMAIL")

	port, err := strconv.Atoi(smtpPort)
	if err != nil {
		log.Fatalf("Invalid SMTP port: %v", err)
	}

	return &SmtpSubscriber{
		smtpHost:     smtpHost,
		smtpPort:     port,
		smtpUser:     smtpUser,
		smtpPassword: smtpPassword,
		fromEmail:    fromEmail,
		toEmail:      toEmail,
	}
}

func (s *SmtpSubscriber) OnDomainChange(domain, oldStatus, newStatus string) {
	msg := fmt.Sprintf("Subject: Domain Status Change\r\n\r\nDomain: %s\nOld Status: %s\nNew Status: %s",
		domain, oldStatus, newStatus)

	auth := smtp.PlainAuth("", s.smtpUser, s.smtpPassword, s.smtpHost)
	addr := fmt.Sprintf("%s:%d", s.smtpHost, s.smtpPort)

	err := smtp.SendMail(addr, auth, s.fromEmail, []string{s.toEmail}, []byte(msg))
	if err != nil {
		log.Printf("Failed to send email notification: %v", err)
	}
}
