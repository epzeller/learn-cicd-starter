package auth

import (
	"errors"
	"net/http"
	"testing"
)

// Define the error variable if not already defined
// var ErrNoAuthHeaderIncluded = errors.New("authorization header not included")

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "Valid ApiKey header",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-api-key"}},
			expectedKey: "my-secret-api-key",
			expectedErr: ErrNoAuthHeaderIncluded,  // change this back to nil
		},
		{
			name:        "Missing Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed header - no space",
			headers:     http.Header{"Authorization": []string{"ApiKeyMySecret"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed header - wrong prefix",
			headers:     http.Header{"Authorization": []string{"Token my-secret-api-key"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Empty token after prefix",
			headers:     http.Header{"Authorization": []string{"ApiKey "}},
			expectedKey: "",
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if tt.expectedErr != nil {
				if err == nil || err.Error() != tt.expectedErr.Error() {
					t.Errorf("expected error '%v', got '%v'", tt.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got '%v'", err)
				}
			}
			if key != tt.expectedKey {
				t.Errorf("expected key '%s', got '%s'", tt.expectedKey, key)
			}
		})
	}
}
