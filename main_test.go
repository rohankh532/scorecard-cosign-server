package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRequest(t *testing.T) {
	payload, _ := ioutil.ReadFile("results.sarif")
	r, _ := http.NewRequest("POST", "/projects", bytes.NewBuffer(payload))
	w := httptest.NewRecorder()

	verifySignature(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}
