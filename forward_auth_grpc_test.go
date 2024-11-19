package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"testing"

	pb "github.com/morzan1001/forward_auth_grpc_plugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// setupTestWithConfig sets up a gRPC server with the given configuration and mock service.
func setupTestWithConfig(t *testing.T, mock pb.AuthServiceServer, config *Config) (*GRPCForwardAuth, func()) {
	lis, err := net.Listen("tcp", config.Address)
	require.NoError(t, err)

	var s *grpc.Server

	if config.UseTLS {
		var creds credentials.TransportCredentials

		if config.CACertPath != "" {
			// If only one CA certificate is provided, we use a self-signed certificate
			cert, err := tls.LoadX509KeyPair("certs/dummy-server.crt", "certs/dummy-server.key")
			require.NoError(t, err)

			caCert, err := os.ReadFile(config.CACertPath)
			require.NoError(t, err)

			caCertPool := x509.NewCertPool()
			ok := caCertPool.AppendCertsFromPEM(caCert)
			require.True(t, ok, "Failed to parse CA certificate")

			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientCAs:    caCertPool,
			}
			creds = credentials.NewTLS(tlsConfig)
		} else {
			t.Fatal("TLS activated, but neither server certificate nor CA certificate specified")
		}

		s = grpc.NewServer(grpc.Creds(creds))
	} else {
		s = grpc.NewServer()
	}

	pb.RegisterAuthServiceServer(s, mock)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	auth, err := New(config)
	require.NoError(t, err)

	cleanup := func() {
		s.Stop()
		lis.Close()
	}

	return auth, cleanup
}

// TestGRPCForwardAuth_FailedAuthentication tests failed authentication.
func TestGRPCForwardAuth_FailedAuthentication(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: false,
		message:   "invalid token",
	}

	config := &Config{
		Address:     "localhost:50052",
		TokenHeader: "Authorization",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	req := NewMockRequest()
	resp := NewMockResponse()

	req.Headers().Set("Authorization", "Bearer invalid-token")

	next, _ := auth.handleRequest(req, resp)

	assert.False(t, next)
	assert.Equal(t, uint32(http.StatusUnauthorized), resp.GetStatusCode())
}

// TestGRPCForwardAuth_MissingToken tests the behavior when the token is missing.
func TestGRPCForwardAuth_MissingToken(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50053",
		TokenHeader: "Authorization",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	req := NewMockRequest()
	resp := NewMockResponse()

	next, _ := auth.handleRequest(req, resp)

	assert.False(t, next)
	assert.Equal(t, uint32(http.StatusUnauthorized), resp.GetStatusCode())
}

// TestGRPCForwardAuth_EmptyToken tests the behavior when the token is empty.
func TestGRPCForwardAuth_EmptyToken(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50054",
		TokenHeader: "Authorization",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	req := NewMockRequest()
	resp := NewMockResponse()

	req.Headers().Set("Authorization", "")

	next, _ := auth.handleRequest(req, resp)

	assert.False(t, next)
	assert.Equal(t, uint32(http.StatusUnauthorized), resp.GetStatusCode())
}

// TestGRPCForwardAuth_WithTLSAndCACert tests the behavior with TLS and CA certificate.
func TestGRPCForwardAuth_WithTLSAndCACert(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50055",
		TokenHeader: "Authorization",
		UseTLS:      true,
		CACertPath:  "certs/dummy-ca.crt",
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	req := NewMockRequest()
	resp := NewMockResponse()

	req.Headers().Set("Authorization", "Bearer valid-token")

	next, _ := auth.handleRequest(req, resp)

	assert.True(t, next)
	assert.Equal(t, uint32(200), resp.GetStatusCode())
}

// TestGRPCForwardAuth_WithoutTLS tests the behavior without TLS.
func TestGRPCForwardAuth_WithoutTLS(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50056",
		TokenHeader: "Authorization",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	req := NewMockRequest()
	resp := NewMockResponse()

	req.Headers().Set("Authorization", "Bearer valid-token")

	next, _ := auth.handleRequest(req, resp)

	assert.True(t, next)
	assert.Equal(t, uint32(200), resp.GetStatusCode())
}

// TestGRPCForwardAuth_EmptyAddress tests the behavior with an empty address.
func TestGRPCForwardAuth_EmptyAddress(t *testing.T) {
	config := &Config{
		Address:     "",
		TokenHeader: "Authorization",
		UseTLS:      false,
	}

	_, err := New(config)
	assert.Error(t, err)
}

// TestGRPCForwardAuth_InvalidCACertPath tests the behavior with an invalid CA certificate path.
func TestGRPCForwardAuth_InvalidCACertPath(t *testing.T) {
	config := &Config{
		Address:     "localhost:50057",
		TokenHeader: "Authorization",
		UseTLS:      true,
		CACertPath:  "nonexistent.crt",
	}

	_, err := New(config)
	assert.Error(t, err)
}

// TestGRPCForwardAuth_CustomTokenHeader tests the behavior with a custom token header.
func TestGRPCForwardAuth_CustomTokenHeader(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50058",
		TokenHeader: "X-Custom-Token",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	req := NewMockRequest()
	resp := NewMockResponse()

	req.Headers().Set("X-Custom-Token", "Bearer valid-token")

	next, _ := auth.handleRequest(req, resp)

	assert.True(t, next)
	assert.Equal(t, uint32(200), resp.GetStatusCode())
}

// TestGRPCForwardAuth_MetadataHandling tests the handling of complex metadata.
func TestGRPCForwardAuth_MetadataHandling(t *testing.T) {
	complexMetadata := map[string]string{
		"user-id":     "123",
		"role":        "admin",
		"permissions": "read,write",
		"tenant":      "org1",
	}

	mock := &MockAuthService{
		allowAuth: true,
		metadata:  complexMetadata,
	}

	config := &Config{
		Address:     "localhost:50059",
		TokenHeader: "Authorization",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	req := NewMockRequest()
	resp := NewMockResponse()

	req.Headers().Set("Authorization", "Bearer valid-token")

	next, _ := auth.handleRequest(req, resp)

	assert.True(t, next)
	for key, value := range complexMetadata {
		headerValue, ok := req.Headers().Get(key)
		assert.True(t, ok)
		assert.Equal(t, value, headerValue)
	}
}

// TestGRPCForwardAuth_ServiceUnavailable tests the behavior when the auth service is unavailable.
func TestGRPCForwardAuth_ServiceUnavailable(t *testing.T) {
	config := &Config{
		Address:     "invalid:50060",
		TokenHeader: "Authorization",
		UseTLS:      false,
	}

	// Directly initialize the service without setting up a gRPC server
	auth, err := New(config)
	require.NoError(t, err)

	req := NewMockRequest()
	resp := NewMockResponse()

	req.Headers().Set("Authorization", "Bearer valid-token")

	next, _ := auth.handleRequest(req, resp)

	assert.False(t, next, "Request should not be forwarded when auth service is unavailable")
	assert.Equal(t, uint32(http.StatusUnauthorized), resp.GetStatusCode(),
		"Should return 401 Unauthorized when auth service is not reachable")

	// Test which error message is returned.
	// In order not to leak any internal information, a standard code with a standard message is expected.
	body := resp.Body().(*MockBody)
	assert.Contains(t, string(body.data), "authentication failed")
}
