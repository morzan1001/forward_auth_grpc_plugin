package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"

	pb "github.com/morzan1001/forward-auth-grpc-plugin/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Config holds the configuration for the GRPCForwardAuth plugin.
type Config struct {
	Address     string
	TokenHeader string
	UseTLS      bool
	CACertPath  string
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

	// Setup connection options
	var opts []grpc.DialOption

	if config.UseTLS {
		var caCertPool *x509.CertPool
		if config.CACertPath != "" {
			// Load the CA certificates
			caCert, err := os.ReadFile(config.CACertPath)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to read CA certificate: %v", err)
			}

			// Create a CertPool and add the CA certificates
			caCertPool = x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, status.Errorf(codes.Internal, "failed to append CA certificate")
			}
		} else {
			// Use the system CA certificates
			var err error
			caCertPool, err = x509.SystemCertPool()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to load system CA certificates: %v", err)
			}
		}

		// Create the TLS credentials
		tlsConfig := &tls.Config{
			RootCAs: caCertPool,
		}

		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// If a test dialer is present, use it
	if dialer, ok := ctx.Value("dialer").(func(context.Context, string) (net.Conn, error)); ok {
		opts = append(opts, grpc.WithContextDialer(dialer))
	}

	conn, err := grpc.NewClient(
		config.Address,
		opts...,
	)

	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to connect to auth service: %v", err)
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
