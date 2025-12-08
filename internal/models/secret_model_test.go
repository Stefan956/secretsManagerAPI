package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test that JSON marshaling uses the expected json tag keys.
func TestSecretStructs_JSONMarshal_Keys(t *testing.T) {
	t.Run("SecretRequest keys", func(t *testing.T) {
		req := SecretRequest{
			SecretName: "my-secret",
			Data: map[string]string{
				"foo": "bar",
			},
		}

		b, err := json.Marshal(req)
		require.NoError(t, err, "marshal should succeed")

		// decode into generic map to inspect keys
		var m map[string]json.RawMessage
		err = json.Unmarshal(b, &m)
		require.NoError(t, err, "unmarshal into map should succeed")

		// check keys produced by json tags
		_, hasName := m["secret-name"]
		_, hasData := m["data"]

		assert.True(t, hasName, "expected 'secret-name' key in JSON")
		assert.True(t, hasData, "expected 'data' key in JSON")
	})

	t.Run("SecretResponse keys", func(t *testing.T) {
		resp := SecretResponse{
			SecretName: "my-secret",
			Data:       map[string]string{"k": "v"},
		}

		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		err = json.Unmarshal(b, &m)
		require.NoError(t, err)

		assert.Contains(t, m, "secret-name")
		assert.Contains(t, m, "data")
	})

	t.Run("SecretListResponse keys", func(t *testing.T) {
		list := SecretListResponse{Secrets: []string{"one", "two"}}
		b, err := json.Marshal(list)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		err = json.Unmarshal(b, &m)
		require.NoError(t, err)

		assert.Contains(t, m, "secrets")
	})
}

// Table-driven test for unmarshalling various payloads into SecretRequest.
func TestSecretRequest_JSONUnmarshal_Validations(t *testing.T) {
	tests := []struct {
		name         string
		jsonPayload  string
		expectErr    bool // json.Unmarshall error (not validation; here we use zero-value checks)
		expectValid  bool // whether required fields are present (we check SecretName and Data)
		expectNilMap bool // whether Data becomes nil after unmarshal
	}{
		{
			name:        "valid payload",
			jsonPayload: `{"secret-name":"s1","data":{"k":"v"}}`,
			expectErr:   false,
			expectValid: true,
		},
		{
			name:        "missing secret-name",
			jsonPayload: `{"data":{"k":"v"}}`,
			expectErr:   false,
			expectValid: false, // secret-name missing -> invalid for API
		},
		{
			name:        "missing data",
			jsonPayload: `{"secret-name":"s1"}`,
			expectErr:   false,
			expectValid: false, // data missing -> invalid for API
			// Data will be nil after unmarshal
			expectNilMap: true,
		},
		{
			name:        "data empty object",
			jsonPayload: `{"secret-name":"s1","data":{}}`,
			expectErr:   false,
			expectValid: true, // present but empty is still "present" (depends on your API rules)
		},
		{
			name:        "bad json",
			jsonPayload: `{"secret-name":"s1", "data":`,
			expectErr:   true,
			expectValid: false,
		},
		{
			name:        "extra fields allowed",
			jsonPayload: `{"secret-name":"s1","data":{"a":"b"},"extra":"x"}`,
			expectErr:   false,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		tc := tc // capture
		t.Run(tc.name, func(t *testing.T) {
			var sr SecretRequest
			err := json.Unmarshal([]byte(tc.jsonPayload), &sr)
			if tc.expectErr {
				require.Error(t, err, "expected json unmarshal error")
				return
			}
			require.NoError(t, err, "unexpected json unmarshal error")

			// simple "validation" for required semantics:
			hasName := sr.SecretName != ""
			hasData := sr.Data != nil // presence vs nil; your API's "required" might demand not nil AND non-empty

			if tc.expectValid {
				assert.True(t, hasName, "expected secret-name to be present")
				assert.True(t, hasData, "expected data to be present (non-nil)")
			} else {
				// at least one required piece should be missing
				if tc.expectNilMap {
					assert.Nil(t, sr.Data, "expected Data to be nil")
				} else {
					assert.False(t, hasName && hasData, "expected at least one required value missing")
				}
			}
		})
	}
}

// Round-trip marshal/unmarshal for SecretResponse and SecretListResponse
func TestSecretResponse_RoundTripJSON(t *testing.T) {
	orig := SecretResponse{
		SecretName: "rt-secret",
		Data:       map[string]string{"k": "v"},
	}
	b, err := json.Marshal(orig)
	require.NoError(t, err)

	var decoded SecretResponse
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)

	assert.Equal(t, orig.SecretName, decoded.SecretName)
	assert.Equal(t, orig.Data, decoded.Data)
}

func TestSecretListResponse_RoundTripJSON(t *testing.T) {
	orig := SecretListResponse{
		Secrets: []string{"a", "b"},
	}
	b, err := json.Marshal(orig)
	require.NoError(t, err)

	var decoded SecretListResponse
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)

	assert.Equal(t, orig.Secrets, decoded.Secrets)
}
