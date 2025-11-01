package events

import (
	"domain-tool-updater/models"
	"time"
)

type EventType string

const (
	EventTypeDmarc       EventType = "UPDATE_DMARC"
	EventTypeSpf         EventType = "UPDATE_SPF"
	EventTypeNameservers EventType = "UPDATE_NAMESERVERS"
)

type EventAction string

const (
	EventActionChange EventAction = "ACTION_CHANGE"
	EventActionInsert EventAction = "ACTION_INSERT"
)

type Event struct {
	EventType      EventType
	EventAction    EventAction
	ExecuteTime    time.Time
	DomainInfo     models.DomainInfo
	DomainInfoPrev models.DomainInfo
}

func (e Event) GetEventType() EventType {
	return e.EventType
}

func (e Event) GetDomainInfo() models.DomainInfo {
	return e.DomainInfo
}

func (e Event) GetEventAction() EventAction {
	return e.EventAction
}
