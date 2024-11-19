package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	pb "github.com/morzan1001/forward_auth_grpc_plugin/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Config holds the configuration for the GRPCForwardAuth plugin.
type Config struct {
	Address     string `json:"address,omitempty"`
	TokenHeader string `json:"tokenHeader,omitempty"`
	UseTLS      bool   `json:"useTLS,omitempty"`
	CACertPath  string `json:"caCertPath,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// GRPCForwardAuth plugin.
type GRPCForwardAuth struct {
	address     string
	tokenHeader string
	client      pb.AuthServiceClient
}

// New creates a new GRPCForwardAuth plugin.
func New(config *Config) (*GRPCForwardAuth, error) {
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

	conn, err := grpc.NewClient(config.Address, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to connect to auth service: %v", err)
	}

	client := pb.NewAuthServiceClient(conn)

	return &GRPCForwardAuth{
		address:     config.Address,
		tokenHeader: config.TokenHeader,
		client:      client,
	}, nil
}

func (g *GRPCForwardAuth) handleRequest(req api.Request, resp api.Response) (next bool, reqCtx uint32) {
	// Get token from header
	token, ok := req.Headers().Get(g.tokenHeader)
	if !ok || token == "" {
		resp.SetStatusCode(http.StatusUnauthorized)
		resp.Body().Write([]byte("missing token"))
		return false, 0
	}

	// Create auth request
	authReq := &pb.AuthRequest{
		Token: token,
	}

	// Call auth service
	ctx := context.Background()
	authResp, err := g.client.Authenticate(ctx, authReq)
	if err != nil || authResp == nil || !authResp.Allowed {
		resp.SetStatusCode(http.StatusUnauthorized)
		if authResp != nil && authResp.Message != "" {
			resp.Body().Write([]byte(authResp.Message))
		} else {
			resp.Body().Write([]byte("authentication failed"))
		}
		return false, 0
	}

	// Add headers from auth response to the original request
	for key, value := range authResp.Metadata {
		req.Headers().Set(key, value)
	}

	return true, 0
}

// main is the entry point for the Wasm module.
func main() {
	var config Config
	err := json.Unmarshal(handler.Host.GetConfig(), &config)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not load config %v", err))
		os.Exit(1)
	}

	mw, err := New(&config)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not load config %v", err))
		os.Exit(1)
	}
	handler.HandleRequestFn = mw.handleRequest
}
