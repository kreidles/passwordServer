/*
* A few unit tests for our REST API endpoints
*
*/
package main

import (
	// "fmt"
	"net/http"
	"net/http/httptest"
	// "net/url"
	"testing"
	"strings"
	// "strconv"
)


// TestHashHandle makes sure we get a valid response from the hash endpoint
func TestHashHandleNoPassword(t *testing.T) {
	
	req, err := http.NewRequest("POST", "/hash", nil)
    if err != nil {
        t.Fatal(err)
    }

    // We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(createPasswordHash)

    // Our handlers satisfy http.Handler, so we can call their ServeHTTP method 
    // directly and pass in our Request and ResponseRecorder.
    handler.ServeHTTP(rr, req)

    // Check the status code is what we expect.
    if status := rr.Code; status != http.StatusBadRequest {
        t.Errorf("handler returned wrong status code: got %v want %v",
            status, http.StatusOK)
    }

    // Check the response body is what we expect.
    expected := `{"msg": "No password specified"}`
    if strings.TrimSpace(rr.Body.String()) != expected {
        t.Errorf("handler returned unexpected body: got %v want %v",
            rr.Body.String(), expected)
    }
}


// TestStatsHandle makes sure we get a valid response from the stats endpoint
func TestStatsHandle(t *testing.T) {

	req, err := http.NewRequest("GET", "/stats", nil)
    if err != nil {
        t.Fatal(err)
    }

    // We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(getStats)

    // Our handlers satisfy http.Handler, so we can call their ServeHTTP method 
    // directly and pass in our Request and ResponseRecorder.
    handler.ServeHTTP(rr, req)

    // Check the status code is what we expect.
    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v",
            status, http.StatusOK)
    }

    // Check the response body is what we expect.
    expected := `{"total": 0, "average": NaN}`
    if rr.Body.String() != expected {
        t.Errorf("handler returned unexpected body: got %v want %v",
            rr.Body.String(), expected)
    }
}

