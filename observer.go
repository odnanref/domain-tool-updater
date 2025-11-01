package main

import (
	"domain-tool-updater/events"
)

type Subscribers interface {
	Update(event events.Event)
}

type Observer struct {
	Subscribers []Subscribers
}

func (o *Observer) Update(event events.Event) {
	switch event.GetEventType() {
	case events.EventTypeDmarc:
		// Handle DMARC update event
	case events.EventTypeSpf:
		// Handle SPF update event
	case events.EventTypeNameservers:
		// Handle Nameservers update event
	}
}

func (o *Observer) Notify(event events.Event) {
	for _, subscriber := range o.Subscribers {
		subscriber.Update(event)
	}
}

func (o *Observer) RegisterSubscriber(subscriber Subscribers) {
	o.Subscribers = append(o.Subscribers, subscriber)
}

func (o *Observer) UnregisterSubscriber(subscriber Subscribers) {
	for i, sub := range o.Subscribers {
		if sub == subscriber {
			o.Subscribers = append(o.Subscribers[:i], o.Subscribers[i+1:]...)
			break
		}
	}
}
