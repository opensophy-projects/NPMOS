package testutils

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"openappsec.io/errors/errorloader"
)

// ErrorResponseCheck gets a response and asserts it contains the desired response code and message
func ErrorResponseCheck(t *testing.T, respBody []byte, wantedErrCode string, wantedMessage string) {
	var res errorloader.ErrorResponse
	if err := json.Unmarshal(respBody, &res); err != nil {
		t.Fatalf("failed to unmarshal body: got err %s", err.Error())
	}

	if res.MessageID != wantedErrCode {
		t.Errorf("handler returned unexpected messegeID in error response: got %v want %v", res.MessageID, wantedErrCode)
	}

	if wantedMessage != "" && res.Message != wantedMessage {
		t.Errorf("handler returned unexpected message in error response: got '%v' want '%v'", res.Message, wantedMessage)
	}
}

// HeadersCheck gets a map of headers and asserts they match the desired headers map
func HeadersCheck(t *testing.T, headers map[string][]string, wantedHeaders map[string]string) {
	if wantedHeaders != nil {
		for k, v := range wantedHeaders {
			if res := headers[k]; len(res) != 0 {
				if res[0] != v {
					t.Errorf("handler returned wrong header value for key (%s): got %s want %s", k, res[0], v)
				}
			}
		}
	}
}

// StatusCodeCheck gets a http response and asserts it contains the desired status code
func StatusCodeCheck(t *testing.T, rr *http.Response, wantedStatus int) {
	if rr.StatusCode != wantedStatus {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.StatusCode, wantedStatus)
	}
}

// TestRequest gets a http server, method, path and body and executes a request using the given parameters
func TestRequest(t *testing.T, ts *httptest.Server, method string, path string, body io.Reader) (*http.Response, []byte) {
	return TestRequestWithHeaders(t, ts, method, path, map[string]string{}, body)
}

// TestRequestWithHeaders gets a http server, method, path, body and headers and executes a request using the given parameters
func TestRequestWithHeaders(t *testing.T, ts *httptest.Server, method string, path string, headers map[string]string, body io.Reader) (*http.Response, []byte) {
	url := ts.URL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
		return nil, []byte{}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
		return nil, []byte{}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
		return nil, []byte{}
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("failed to load file. Error: %v", err.Error())
		}
	}()

	return resp, respBody
}
