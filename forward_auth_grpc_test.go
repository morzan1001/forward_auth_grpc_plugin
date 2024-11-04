package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"

	pb "github.com/morzan1001/forward_auth_grpc_plugin/proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// MockServerTransportStream implements grpc.ServerTransportStream for tests
type MockServerTransportStream struct {
	headersSent metadata.MD
}

func (m *MockServerTransportStream) Method() string                 { return "" }
func (m *MockServerTransportStream) SetHeader(md metadata.MD) error { return nil }
func (m *MockServerTransportStream) SendHeader(md metadata.MD) error {
	m.headersSent = md
	return nil
}
func (m *MockServerTransportStream) SetTrailer(md metadata.MD) error { return nil }

// MockAuthService is a mock for the external service
type MockAuthService struct {
	pb.UnimplementedAuthServiceServer
	allowAuth bool
	metadata  map[string]string
}

// Authenticate is the mock implementation of the Authenticate method
func (m *MockAuthService) Authenticate(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	return &pb.AuthResponse{
		Allowed:  m.allowAuth,
		Message:  "mock response",
		Metadata: m.metadata,
	}, nil
}

func setupTestWithConfig(t *testing.T, mock *MockAuthService, config *Config) (*GRPCForwardAuth, func()) {
	// Start mock server
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

	// Create GRPCForwardAuth instance with configuration
	auth, err := New(context.Background(), config, "test")
	require.NoError(t, err)

	cleanup := func() {
		s.Stop()
	}

	return auth, cleanup
}

func TestGRPCForwardAuth_WithMetadata(t *testing.T) {
	expectedMetadata := map[string]string{
		"user-id": "123",
		"role":    "admin",
	}

	mock := &MockAuthService{
		allowAuth: true,
		metadata:  expectedMetadata,
	}

	config := &Config{
		Address:     "localhost:50051",
		TokenHeader: "authorization",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	// Create stream mock
	stream := &MockServerTransportStream{}

	// Context with stream and token
	ctx := grpc.NewContextWithServerTransportStream(
		metadata.NewIncomingContext(
			context.Background(),
			metadata.New(map[string]string{
				"authorization": "Bearer valid-token",
			}),
		),
		stream,
	)

	// Execute request
	err := auth.InterceptRequest(ctx)
	require.NoError(t, err)

	// Check whether metadata has been passed on correctly
	require.NotNil(t, stream.headersSent)
	assert.Equal(t, expectedMetadata["user-id"], stream.headersSent.Get("user-id")[0])
	assert.Equal(t, expectedMetadata["role"], stream.headersSent.Get("role")[0])
}

func TestGRPCForwardAuth_WithCACert(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	config := &Config{
		Address:     "localhost:50052",
		TokenHeader: "authorization",
		UseTLS:      true,
		CACertPath:  "certs/dummy-ca.crt",
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
		Address:     "localhost:50053",
		TokenHeader: "authorization",
		UseTLS:      true,
		CACertPath:  "certs/dummy-server.crt",
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

func TestGRPCForwardAuth_InvalidToken(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: false, // Set to false to simulate authentication failure
	}

	config := &Config{
		Address:     "localhost:50054",
		TokenHeader: "authorization",
		UseTLS:      false,
	}

	auth, cleanup := setupTestWithConfig(t, mock, config)
	defer cleanup()

	// Create context with invalid token
	md := metadata.New(map[string]string{
		"authorization": "Bearer invalid-token",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Test authentication
	err := auth.InterceptRequest(ctx)

	// Verify error
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Contains(t, st.Message(), "mock response")
}

func TestGRPCForwardAuth_NoTLS(t *testing.T) {
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
		Address:     "localhost:50056",
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

	config := &Config{
		Address:     "invalid-address:50057",
		TokenHeader: "authorization",
		UseTLS:      false,
	}

	// Create context with token
	md := metadata.New(map[string]string{
		"authorization": "Bearer token",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

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
