package dnsquery

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestGetTXTRecords_UsesLookupTXTImpl(t *testing.T) {
	old := lookupTXTImpl
	defer func() { lookupTXTImpl = old }()

	lookupTXTImpl = func(domain string) ([]string, error) {
		if domain != "example.com" {
			t.Fatalf("unexpected domain: %s", domain)
		}
		return []string{"v=spf1 include:_spf.example.com ~all", "some other txt"}, nil
	}

	recs, err := GetTXTRecords("example.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
}

func TestGetSPFRecord_FindsRecord(t *testing.T) {
	old := lookupTXTImpl
	defer func() { lookupTXTImpl = old }()

	lookupTXTImpl = func(domain string) ([]string, error) {
		return []string{"v=spf1 include:_spf.example.com ~all", "other"}, nil
	}

	rec, err := GetSPFRecord("example.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rec == "" {
		t.Fatalf("expected spf record, got empty")
	}
}

func TestGetSPFRecord_NotFound(t *testing.T) {
	old := lookupTXTImpl
	defer func() { lookupTXTImpl = old }()

	lookupTXTImpl = func(domain string) ([]string, error) {
		return []string{"not spf"}, nil
	}

	_, err := GetSPFRecord("example.com")
	if err == nil {
		t.Fatalf("expected error when spf not found")
	}
}

func TestGetDMARCRecord_FindsRecord(t *testing.T) {
	old := lookupTXTImpl
	defer func() { lookupTXTImpl = old }()

	lookupTXTImpl = func(domain string) ([]string, error) {
		// domain will be _dmarc.example.com
		if domain != "_dmarc.example.com" {
			t.Fatalf("unexpected domain: %s", domain)
		}
		return []string{"v=DMARC1; p=none; rua=mailto:postmaster@example.com"}, nil
	}

	rec, err := GetDMARCRecord("example.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rec == "" {
		t.Fatalf("expected dmarc record, got empty")
	}
}

func TestGetDKIMRecord_FindsRecord(t *testing.T) {
	old := lookupTXTImpl
	defer func() { lookupTXTImpl = old }()

	lookupTXTImpl = func(domain string) ([]string, error) {
		// selector._domainkey.example.com
		if domain != "selector._domainkey.example.com" {
			t.Fatalf("unexpected domain: %s", domain)
		}
		return []string{"v=DKIM1; k=rsa; p=abcd"}, nil
	}

	rec, err := GetDKIMRecord("example.com", "selector")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rec == "" {
		t.Fatalf("expected dkim record, got empty")
	}
}

func TestGetTXTRecords_b1_ParsesDNSRecords(t *testing.T) {
	old := dnsQueryImpl
	defer func() { dnsQueryImpl = old }()

	// create a fake TXT RR
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"hello", "world"}}
	dnsQueryImpl = func(domain string, qtype uint16) ([]dns.RR, error) {
		if qtype != dns.TypeTXT {
			return nil, errors.New("unexpected qtype")
		}
		return []dns.RR{txt}, nil
	}

	recs, err := GetTXTRecords_b1("example.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0] != "hello world" {
		t.Fatalf("unexpected txt join result: %s", recs[0])
	}
}

func TestGetNSRecords_ParsesDNSRecords(t *testing.T) {
	old := dnsQueryImpl
	defer func() { dnsQueryImpl = old }()

	ns := &dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.com."}
	dnsQueryImpl = func(domain string, qtype uint16) ([]dns.RR, error) {
		if qtype != dns.TypeNS {
			return nil, errors.New("unexpected qtype")
		}
		return []dns.RR{ns}, nil
	}

	recs, err := GetNSRecords("example.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 ns record, got %d", len(recs))
	}
	if recs[0] != "ns1.example.com." {
		t.Fatalf("unexpected ns value: %s", recs[0])
	}
}

func TestGetExpirationDate_ParsesWhois(t *testing.T) {
	old := whoisImpl
	defer func() { whoisImpl = old }()

	whoisImpl = func(domain string) (string, error) {
		return "Registrar: Example Registrar\nRegistry Expiry Date: 2026-10-30T12:00:00Z\nCreation Date: 2020-01-01T00:00:00Z", nil
	}

	exp, err := GetExpirationDate("example.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if exp == "" {
		t.Fatalf("expected expiration date, got empty")
	}
}

func TestGetAllDatesFromWhois_ParsesWhois(t *testing.T) {
	old := whoisImpl
	defer func() { whoisImpl = old }()

	whoisImpl = func(domain string) (string, error) {
		return "Registrar: Example Registrar\nRegistry Expiry Date: 2026-10-30T12:00:00Z\nCreation Date: 2020-01-01T00:00:00Z", nil
	}

	m := GetAllDatesFromWhois("example.com")
	if m["creationDate"] == "" || m["expirationDate"] == "" || m["registrar"] == "" {
		t.Fatalf("expected all fields to be parsed, got: %v", m)
	}
}
