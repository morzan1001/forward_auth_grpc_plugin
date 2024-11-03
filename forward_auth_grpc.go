package forward_auth_grpc_plugin

import (
	"context"
	"net"
	"time"

	pb "github.com/morzan1001/forward-auth-grpc-plugin/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Config the plugin configuration.
type Config struct {
	Address     string `json:"address,omitempty"`     // Auth service address
	TokenHeader string `json:"tokenHeader,omitempty"` // Name of the token metadata field
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TokenHeader: "authorization", // Default token header name
	}
}

// GRPCForwardAuth plugin.
type GRPCForwardAuth struct {
	address     string
	tokenHeader string
	name        string
	client      pb.AuthServiceClient
}

// New creates a new GRPCForwardAuth plugin.
func New(ctx context.Context, config *Config, name string) (*GRPCForwardAuth, error) {
	if config.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "auth service address cannot be empty")
	}

	// Timeout für die initiale Verbindung
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Setup connection options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	// If a test dialer is present, use it
	if dialer, ok := ctx.Value("dialer").(func(context.Context, string) (net.Conn, error)); ok {
		opts = append(opts, grpc.WithContextDialer(dialer))
	}

	conn, err := grpc.DialContext(
		dialCtx,
		config.Address,
		opts...,
	)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to connect to auth service: %v", err)
	}

	// Prüfe den Verbindungsstatus
	state := conn.GetState()
	if state != connectivity.Ready {
		conn.Close()
		return nil, status.Error(codes.Unavailable, "failed to establish connection to auth service")
	}

	client := pb.NewAuthServiceClient(conn)

	return &GRPCForwardAuth{
		address:     config.Address,
		tokenHeader: config.TokenHeader,
		name:        name,
		client:      client,
	}, nil
}

// InterceptRequest handles the incoming gRPC request authentication
func (g *GRPCForwardAuth) InterceptRequest(ctx context.Context) error {
	if g.client == nil {
		return status.Error(codes.Unavailable, "auth client not initialized")
	}

	// Get metadata from incoming request
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Get token from metadata
	tokens := md.Get(g.tokenHeader)
	if len(tokens) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing %s header", g.tokenHeader)
	}
	token := tokens[0]

	// Create auth request
	authReq := &pb.AuthRequest{
		Token: token,
	}

	// Call auth service
	resp, err := g.client.Authenticate(ctx, authReq)
	if err != nil {
		return err
	}

	if !resp.Allowed {
		return status.Error(codes.PermissionDenied, resp.Message)
	}

	// If authentication successful and we have metadata
	if resp.Metadata != nil {
		if stream := grpc.ServerTransportStreamFromContext(ctx); stream != nil {
			return stream.SendHeader(metadata.New(resp.Metadata))
		}
	}

	return nil
}
