package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	pb "github.com/morzan1001/forward-auth-grpc-plugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// MockAuthService is a mock for the external service
type MockAuthService struct {
	pb.UnimplementedAuthServiceServer
	allowAuth bool
}

// Authenticate is the mock implementation of the Authenticate method
func (m *MockAuthService) Authenticate(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	return &pb.AuthResponse{
		Allowed: m.allowAuth,
		Message: "mock response",
	}, nil
}

func setupTestWithConfig(t *testing.T, mock *MockAuthService, config *Config) (*GRPCForwardAuth, func()) {
	// Start mock server
	lis, err := net.Listen("tcp", config.Address)
	require.NoError(t, err)

	var s *grpc.Server

	if config.UseTLS {
		var creds credentials.TransportCredentials

		if config.ServiceCertPath != "" && config.ServiceKeyPath != "" {
			// Load server certificate and key
			cert, err := tls.LoadX509KeyPair(config.ServiceCertPath, config.ServiceKeyPath)
			require.NoError(t, err)

			// Create TLS credentials with server certificate
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
			creds = credentials.NewTLS(tlsConfig)
			t.Log("Server using TLS with ServerCert and ServerKey")
		} else if config.CACertPath != "" {
			// If only one CA certificate is provided, we use a self-signed certificate
			cert, err := tls.LoadX509KeyPair(".assets/dummy-server.crt", ".assets/dummy-server.key")
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
			t.Log("Server using TLS with CACert")
		} else {
			t.Fatal("TLS activated, but neither server certificate nor CA certificate specified")
		}

		s = grpc.NewServer(grpc.Creds(creds))
	} else {
		s = grpc.NewServer()
		t.Log("Server using no TLS")
	}

	pb.RegisterAuthServiceServer(s, mock)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	// Create GRPCForwardAuth instance with configuration
	auth, err := New(context.Background(), config, "test")
	require.NoError(t, err)

	cleanup := func() {
		s.Stop()
	}

	return auth, cleanup
}

func TestGRPCForwardAuth_WithCACert(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50051",
		TokenHeader: "authorization",
		UseTLS:      true,
		CACertPath:  ".assets/dummy-ca.crt",
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	// Create context with token
	md := metadata.New(map[string]string{
		"authorization": "Bearer token",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Test authentication
	err := auth.InterceptRequest(ctx)

	// Verify no error
	assert.NoError(t, err)
}

func TestGRPCForwardAuth_WithServiceCert(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:         "localhost:50052",
		TokenHeader:     "authorization",
		UseTLS:          true,
		ServiceCertPath: ".assets/dummy-server.crt",
		ServiceKeyPath:  ".assets/dummy-server.key",
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	// Create context with token
	md := metadata.New(map[string]string{
		"authorization": "Bearer token",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Test authentication
	err := auth.InterceptRequest(ctx)

	// Verify no error
	assert.NoError(t, err)
}

func TestGRPCForwardAuth_WithSystemCACerts(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50053",
		TokenHeader: "authorization",
		UseTLS:      true,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	// Create context with token
	md := metadata.New(map[string]string{
		"authorization": "Bearer token",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Test authentication
	err := auth.InterceptRequest(ctx)

	// Verify no error
	assert.NoError(t, err)
}

func TestGRPCForwardAuth_NoTLS(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50054",
		TokenHeader: "authorization",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	// Create context with token
	md := metadata.New(map[string]string{
		"authorization": "Bearer token",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Test authentication
	err := auth.InterceptRequest(ctx)

	// Verify no error
	assert.NoError(t, err)
}

func TestGRPCForwardAuth_MissingToken(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50055",
		TokenHeader: "authorization",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	// Create context without token
	md := metadata.New(map[string]string{})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Test authentication
	err := auth.InterceptRequest(ctx)

	// Verify error
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "missing authorization header")
}

func TestGRPCForwardAuth_AuthServiceDown(t *testing.T) {
	// Context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	config := &Config{
		Address:     "invalid-address:50056",
		TokenHeader: "authorization",
		UseTLS:      false,
	}

	auth, err := New(ctx, config, "test")
	if err == nil {
		// If no errors when creating, try a request
		reqCtx := metadata.NewIncomingContext(
			context.Background(),
			metadata.New(map[string]string{
				"authorization": "Bearer test-token",
			}),
		)

		err = auth.InterceptRequest(reqCtx)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.Unavailable, st.Code())
	} else {
		// Or check the connection error
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.Unavailable, st.Code())
	}
}
