// Copyright (c) 2020 BitMaelum Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bitmaelum/bitmaelum-suite/internal/container"
	"github.com/bitmaelum/bitmaelum-suite/internal/webhook"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/gorilla/mux"
)

type inputWebhookType struct {
	Event  webhook.EventEnum `json:"event"`
	Type   webhook.TypeEnum  `json:"type"`
	Config map[string]string `json:"config"`
}

// CreateWebhook is a handler that will create a new webhook
func CreateWebhook(w http.ResponseWriter, req *http.Request) {
	var input inputWebhookType
	err := DecodeBody(w, req.Body, &input)
	if err != nil {
		ErrorOut(w, http.StatusBadRequest, "incorrect body")
		return
	}

	// @TODO check webhook input, and configs

	h, err := hash.NewFromHash(mux.Vars(req)["addr"])
	if err != nil {
		ErrorOut(w, http.StatusNotFound, accountNotFound)
		return
	}

	cfg, err := json.Marshal(input.Config)
	if err != nil {
		ErrorOut(w, http.StatusBadRequest, "incorrect body")
		return
	}

	wh, err := webhook.NewWebhook(*h, input.Event, input.Type, cfg)
	if err != nil {
		ErrorOut(w, http.StatusBadRequest, "incorrect body")
		return
	}

	// Store webhook into persistent storage
	repo := container.Instance.GetWebhookRepo()
	err = repo.Store(*wh)
	if err != nil {
		msg := fmt.Sprintf("error while storing webhook: %s", err)
		ErrorOut(w, http.StatusInternalServerError, msg)
		return
	}

	// Output webhook
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(jsonOut{
		"webhook_id": wh.ID,
	})
}

// ListWebhooks returns a list of all webhooks for the given account
func ListWebhooks(w http.ResponseWriter, req *http.Request) {
	h, err := hash.NewFromHash(mux.Vars(req)["addr"])
	if err != nil {
		ErrorOut(w, http.StatusNotFound, accountNotFound)
		return
	}

	repo := container.Instance.GetWebhookRepo()
	webhooks, err := repo.FetchByHash(*h)
	if err != nil {
		msg := fmt.Sprintf("error while retrieving webhooks: %s", err)
		ErrorOut(w, http.StatusInternalServerError, msg)
		return
	}

	// Output wh
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(webhooks)
}

// DeleteWebhook will remove a webhook
func DeleteWebhook(w http.ResponseWriter, req *http.Request) {
	h, err := hash.NewFromHash(mux.Vars(req)["addr"])
	if err != nil {
		ErrorOut(w, http.StatusNotFound, accountNotFound)
		return
	}

	whID := mux.Vars(req)["id"]

	// Fetch webhook
	repo := container.Instance.GetWebhookRepo()
	wh, err := repo.Fetch(whID)
	if err != nil || wh.Account.String() != h.String() {
		// Only allow deleting of webhooks that we own as account
		ErrorOut(w, http.StatusNotFound, "webhook not found")
		return
	}

	_ = repo.Remove(*wh)

	// All is well
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// GetWebhookDetails will get a webhook
func GetWebhookDetails(w http.ResponseWriter, req *http.Request) {
	h, err := hash.NewFromHash(mux.Vars(req)["addr"])
	if err != nil {
		ErrorOut(w, http.StatusNotFound, accountNotFound)
		return
	}

	whID := mux.Vars(req)["id"]

	// Fetch webhook
	repo := container.Instance.GetWebhookRepo()
	wh, err := repo.Fetch(whID)
	if err != nil || wh.Account.String() != h.String() {
		ErrorOut(w, http.StatusNotFound, "webhook not found")
		return
	}

	// Output webhook
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(wh)
}

// EnableWebhook will enable a webhook
func EnableWebhook(w http.ResponseWriter, req *http.Request) {
	endis(w, req, true)
}

// DisableWebhook will enable a webhook
func DisableWebhook(w http.ResponseWriter, req *http.Request) {
	endis(w, req, false)
}

func endis(w http.ResponseWriter, req *http.Request, status bool) {
	h, err := hash.NewFromHash(mux.Vars(req)["addr"])
	if err != nil {
		ErrorOut(w, http.StatusNotFound, accountNotFound)
		return
	}

	whID := mux.Vars(req)["id"]

	// Fetch webhook
	repo := container.Instance.GetWebhookRepo()
	wh, err := repo.Fetch(whID)
	if err != nil || wh.Account.String() != h.String() {
		ErrorOut(w, http.StatusNotFound, "webhook not found")
		return
	}

	// set wh status
	wh.Enabled = status

	// Store
	err = repo.Store(*wh)
	if err != nil {
		ErrorOut(w, http.StatusInternalServerError, "cannot enable")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}
