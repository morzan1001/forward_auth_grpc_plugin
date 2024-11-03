package forward_auth_grpc_plugin

import (
	"context"
	"net"
	"testing"
	"time"

	pb "github.com/morzan1001/forward-auth-grpc-plugin/proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// MockAuthService implements the Auth Service for tests
type MockAuthService struct {
	pb.UnimplementedAuthServiceServer
	allowAuth    bool
	returnError  error
	returnHeader map[string]string
}

// mockServerTransportStream implements grpc.ServerTransportStream
type mockServerTransportStream struct {
	header  metadata.MD
	trailer metadata.MD
}

func (s *mockServerTransportStream) Method() string                  { return "" }
func (s *mockServerTransportStream) SetHeader(md metadata.MD) error  { s.header = md; return nil }
func (s *mockServerTransportStream) SendHeader(md metadata.MD) error { s.header = md; return nil }
func (s *mockServerTransportStream) SetTrailer(md metadata.MD) error { s.trailer = md; return nil }

func (m *MockAuthService) Authenticate(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	if m.returnError != nil {
		return nil, m.returnError
	}

	return &pb.AuthResponse{
		Allowed:  m.allowAuth,
		Message:  "test message",
		Metadata: m.returnHeader,
	}, nil
}

func setupTest(t *testing.T, mock *MockAuthService) (*GRPCForwardAuth, func()) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterAuthServiceServer(server, mock)

	// Start server in its own goroutine
	serverError := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil {
			serverError <- err
		}
		close(serverError)
	}()

	// Context with timeout for client connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		"",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	auth := &GRPCForwardAuth{
		address:     "bufnet",
		tokenHeader: "authorization",
		name:        "test-auth",
		client:      pb.NewAuthServiceClient(conn),
	}

	cleanup := func() {
		// Graceful Shutdown des Servers
		shutdownDone := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(shutdownDone)
		}()

		// Timeout for shutdown
		select {
		case <-shutdownDone:
			// Server successfully stopped
		case <-time.After(5 * time.Second):
			// Force stop after timeout
			server.Stop()
		}

		conn.Close()
		listener.Close()

		// Check for server errors
		if err := <-serverError; err != nil {
			t.Errorf("server error: %v", err)
		}
	}

	return auth, cleanup
}
func TestGRPCForwardAuth_Success(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
		returnHeader: map[string]string{
			"x-user-id": "123",
			"x-role":    "admin",
		},
	}

	auth, cleanup := setupTest(t, mock)
	defer cleanup()

	// Create stream
	stream := &mockServerTransportStream{
		header: make(metadata.MD),
	}

	// Create test context with server interceptors
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.New(map[string]string{
			"authorization": "Bearer test-token",
		}),
	)
	ctx = grpc.NewContextWithServerTransportStream(ctx, stream)

	// Test authentication
	err := auth.InterceptRequest(ctx)
	assert.NoError(t, err)

	// Verify headers directly from the stream
	assert.Equal(t, []string{"123"}, stream.header["x-user-id"])
	assert.Equal(t, []string{"admin"}, stream.header["x-role"])
}

func TestGRPCForwardAuth_MissingToken(t *testing.T) {
	mock := &MockAuthService{
		allowAuth: true,
	}

	auth, cleanup := setupTest(t, mock)
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
		Address:     "invalid-address:50051",
		TokenHeader: "authorization",
	}

	auth, err := New(ctx, config, "test-auth")
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

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()
	assert.Equal(t, "authorization", config.TokenHeader)
	assert.Empty(t, config.Address)
}

func TestNew(t *testing.T) {
	// Setup Mock Server
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterAuthServiceServer(server, &MockAuthService{})

	go func() {
		if err := server.Serve(listener); err != nil {
			t.Errorf("error serving server: %v", err)
		}
	}()
	defer server.Stop()

	// Helper Funktion für Dial
	dialer := func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}

	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid config",
			config: &Config{
				Address:     "bufnet", // Dummy address, will be overwritten by dialer
				TokenHeader: "authorization",
			},
			expectError: false,
		},
		{
			name: "missing address",
			config: &Config{
				TokenHeader: "authorization",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Overwrite the default dialer for the test
			if !tt.expectError {
				ctx = context.WithValue(ctx, "dialer", dialer)
			}

			auth, err := New(ctx, tt.config, "test-auth")
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, auth)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, auth)
			}
		})
	}
}
