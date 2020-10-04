package api

import (
	"encoding/json"
	"fmt"

	"github.com/bitmaelum/bitmaelum-suite/internal/ticket"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
)

// GetTicket retrieves a ticket that can be used for uploading a message
func (api *API) GetTicket(from, to hash.Hash, subscriptionID string) (*ticket.Ticket, error) {
	data, err := json.MarshalIndent(jsonOut{
		"from_addr":       from.String(),
		"to_addr":         to.String(),
		"subscription_id": subscriptionID,
	}, "", "  ")
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("/account/%s/ticket", from.String())
	body, statusCode, err := api.Post(url, data)
	if err != nil {
		return nil, err
	}

	if statusCode < 200 || statusCode > 299 {
		return nil, errNoSuccess
	}

	if isErrorResponse(body) {
		return nil, getErrorFromResponse(body)
	}

	// Parse body for ticket
	t := &ticket.Ticket{}
	err = json.Unmarshal(body, &t)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// GetAnonymousTicket retrieves a ticket that can be used for uploading a message
func (api *API) GetAnonymousTicket(from, to hash.Hash, subscriptionID string) (*ticket.Ticket, error) {
	data, err := json.MarshalIndent(jsonOut{
		"from_addr":       from.String(),
		"to_addr":         to.String(),
		"subscription_id": subscriptionID,
	}, "", "  ")
	if err != nil {
		return nil, err
	}

	body, statusCode, err := api.Post("/ticket", data)
	if err != nil {
		return nil, err
	}

	if (statusCode < 200 || statusCode > 299) && statusCode != 412 {
		return nil, getErrorFromResponse(body)
	}

	if isErrorResponse(body) {
		return nil, getErrorFromResponse(body)
	}

	// Parse body for ticket
	t := &ticket.Ticket{}
	err = json.Unmarshal(body, &t)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// GetAnonymousTicketByProof will send proof of work for a given ticket ID. If correct, the server will
// return the validated ticket back. From that point on we can use the ticket to send a message.
func (api *API) GetAnonymousTicketByProof(from, to hash.Hash, subscriptionID, ticketID string, proof uint64) (*ticket.Ticket, error) {
	data, err := json.MarshalIndent(jsonOut{
		"from_addr":      from.String(),
		"to_addr":        to.String(),
		"ticket_id":      ticketID,
		"subscriptionId": subscriptionID,
		"proof_of_work":  proof,
	}, "", "  ")
	if err != nil {
		return nil, err
	}

	body, statusCode, err := api.Post("/ticket", data)
	if err != nil {
		return nil, err
	}

	if statusCode < 200 || statusCode > 299 {
		return nil, errNoSuccess
	}

	if isErrorResponse(body) {
		return nil, getErrorFromResponse(body)
	}

	// Parse body for ticket
	newT := &ticket.Ticket{}
	err = json.Unmarshal(body, &newT)
	if err != nil {
		return nil, err
	}

	return newT, nil
}
