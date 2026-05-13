package jsonrpc

import "encoding/json"

// Request is the JSON-RPC-like envelope used by the FortiSandbox API.
// The operation is routed by params[0].url.
type Request struct {
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
	Session string            `json:"session,omitempty"`
	ID      json.RawMessage   `json:"id,omitempty"`
	Version string            `json:"version,omitempty"`
}

type Status struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Result struct {
	URL    string      `json:"url"`
	Status Status      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
}

type Response struct {
	Session string          `json:"session,omitempty"`
	Result  *Result         `json:"result,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

// ParamURL extracts params[0].url without fully decoding the payload.
func ParamURL(raw json.RawMessage) string {
	var p struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(raw, &p)
	return p.URL
}
