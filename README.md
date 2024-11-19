# gRPC Forward Auth Plugin

## Overview

The GRPC Forward Auth Plugin for Traefik allows validating incoming requests against a gRPC authentication service. It forwards authentication requests to the gRPC authentication service and checks the response to decide whether to allow or deny the request.

### Why i created this plugin

I had the problem that my entire backend speaks grpc. all services of a microservice infrastructure communicate with each other via grpc. But I wanted to use traefik to check authentication. Otherwise I would have had to write logic for this in every service. Traefik already offers a [forwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) for http backends. In fact, my first setup was to use this forward auth and then the plugin [http2grcp](https://github.com/v-electrolux/http2grpc), but the constant translation in protocols was a bit unpleasant :smile:

## Installation

To install the plugin, add the following configuration to your Traefik configuration file:

```yaml
experimental:
  plugins:
    grpcForwardAuth:
      moduleName: "github.com/morzan1001/forward_auth_grpc_plugin"
      version: "v1.0.1"
```

### Yaegi vs. Wasm 

Actually I had planned to write a native traefik plugin. Unfortunately [yaegi](https://github.com/traefik/yaegi) (go interpreter of traefik) has the restriction that the package [unsafe](https://pkg.go.dev/unsafe) may not be used. A debatable design decision, but nothing I can influence. Unfortunately, the package protobuf has this dependency and I have not found a way not to use [protobuf](https://pkg.go.dev/google.golang.org/protobuf). So I switched to a wasm plugin. The disadvantage is the conversion of data to json and back so that traefik can talk to the plugin via http. I find this step superfluous but there is currently no other way to delete it. If I have overlooked something, I would be happy to receive an issue.

## Configuration

The plugin is configured via the `traefik.yml` file. Here is an example:

```yaml
http:
  middlewares:
    my-grpc-forward-auth:
      plugin:
        grpcForwardAuth:
          address: "localhost:50051"
          tokenHeader: "authorization"
          useTLS: false
          caCertPath: "" 
```

### Parameters

- `address`: The address of the gRPC authentication service.
- `tokenHeader`: The name of the header that contains the authentication token.
- `useTLS`: Setting whether the authentication service should be called using tls
- `caCertPath`: If an internal CA is used, the certificate can be specified here.

#### TLS

The plugin can communicate with unencrypted (h2c) grpc services as well as with services via TLS. If no extra CA or server certificate is specified, the CAs stored in the system are used.

### Exampe gRPC Auth Service configuration

The gRPC authentication service must implement the following endpoints to be compatible with the plugin:

#### proto/auth.proto

```proto3
syntax = "proto3";

package proto;

option go_package = "github.com/morzan1001/forward-auth-grpc-plugin/proto";

// AuthService handles authentication requests
service AuthService {
    rpc Authenticate(AuthRequest) returns (AuthResponse);
}

// AuthRequest contains the authentication token
message AuthRequest {
    string token = 1;
}

// AuthResponse contains the authentication result
message AuthResponse {
    bool allowed = 1;
    string message = 2;
    map<string, string> metadata = 3;
}
```

#### AuthService Implementation

```go
package main

import (
    "context"
    "net"

    pb "github.com/morzan1001/forward-auth-grpc-plugin/proto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

type AuthServiceServer struct {
    pb.UnimplementedAuthServiceServer
}

func (s *AuthServiceServer) Authenticate(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
    // Implement your authentication logic here
    if req.Token == "valid-token" {
        return &pb.AuthResponse{
            Allowed: true,
            Message: "Authentication successful",
        }, nil
    }
    return &pb.AuthResponse{
        Allowed: false,
        Message: "Authentication failed",
    }, status.Error(codes.Unauthenticated, "invalid token")
}

func main() {
    lis, err := net.Listen("tcp", ":50051")
    if err != nil {
        panic(err)
    }
    grpcServer := grpc.NewServer()
    pb.RegisterAuthServiceServer(grpcServer, &AuthServiceServer{})
    if err := grpcServer.Serve(lis); err != nil {
        panic(err)
    }
}
```

### Tests

To test the plugin, you can use the provided unit tests. Run the tests with the following command:

```bash
go test ./...
```

or

```bash
make test
```

### License

This project is licensed under the MIT License. See the LICENSE file for more details.
