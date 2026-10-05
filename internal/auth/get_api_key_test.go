package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers   http.Header
		want      strin
		wantErr   error
		expectErr bool
	}{
		"no authorization header": {
			headers:   http.Header{},
			want:      "",
			wantErr:   ErrNoAuthHeaderIncluded,
			expectErr: true,
		},
		"empty authorization header": {
			headers:   http.Header{"Authorization": []string{""}},
			want:      "",
			wantErr:   ErrNoAuthHeaderIncluded,
			expectErr: true,
		},
		"malformed - missing ApiKey prefix": {
			headers:   http.Header{"Authorization": []string{"Bearer sometoken"}},
			want:      "",
			expectErr: true,
		},
		"malformed - only one field": {
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			want:      "",
			expectErr: true,
		},
		"valid api key": {
			headers:   http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			want:      "my-secret-key",
			expectErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			if got != tc.want {
				t.Errorf("expected key: %q, got: %q", tc.want, got)
			}

			if tc.expectErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			// For sentinel errors, verify the exact error is returned.
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("expected error: %v, got: %v", tc.wantErr, err)
			}
		})
	}
}
