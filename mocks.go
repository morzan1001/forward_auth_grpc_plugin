package main

import (
	"context"
	"io"

	pb "github.com/morzan1001/forward_auth_grpc_plugin/proto"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

type MockHeaders struct {
	headers map[string][]string
}

func NewMockHeaders() *MockHeaders {
	return &MockHeaders{headers: make(map[string][]string)}
}

func (m *MockHeaders) Get(key string) (string, bool) {
	values, ok := m.headers[key]
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func (m *MockHeaders) GetAll(key string) []string {
	if values, ok := m.headers[key]; ok {
		return values
	}
	return []string{}
}

func (m *MockHeaders) Names() []string {
	names := make([]string, 0, len(m.headers))
	for name := range m.headers {
		names = append(names, name)
	}
	return names
}

func (m *MockHeaders) Set(key, value string) {
	m.headers[key] = []string{value}
}

func (m *MockHeaders) Add(key, value string) {
	m.headers[key] = append(m.headers[key], value)
}

func (m *MockHeaders) Remove(key string) {
	delete(m.headers, key)
}

func (m *MockHeaders) Keys() []string {
	keys := make([]string, 0, len(m.headers))
	for key := range m.headers {
		keys = append(keys, key)
	}
	return keys
}

type MockBody struct {
	data    []byte
	readPos uint32
}

func NewMockBody() *MockBody {
	return &MockBody{
		data:    []byte{},
		readPos: 0,
	}
}

func (b *MockBody) Read(p []byte) (uint32, bool) {
	if b.readPos >= uint32(len(b.data)) {
		return 0, true // EOF erreicht
	}
	n := copy(p, b.data[b.readPos:])
	b.readPos += uint32(n)
	eof := b.readPos >= uint32(len(b.data))
	return uint32(n), eof
}

func (b *MockBody) Write(p []byte) {
	b.data = append(b.data, p...)
}

func (b *MockBody) WriteString(s string) {
	b.data = append(b.data, []byte(s)...)
}

func (b *MockBody) WriteTo(w io.Writer) (uint64, error) {
	n, err := w.Write(b.data)
	return uint64(n), err
}

type MockRequest struct {
	headers    api.Header
	method     string
	uri        string
	body       api.Body
	sourceAddr string
}

func NewMockRequest() *MockRequest {
	return &MockRequest{
		headers:    NewMockHeaders(),
		body:       NewMockBody(),
		sourceAddr: "127.0.0.1:12345",
	}
}

func (r *MockRequest) Headers() api.Header {
	return r.headers
}

func (r *MockRequest) GetMethod() string {
	return r.method
}

func (r *MockRequest) SetMethod(method string) {
	r.method = method
}

func (r *MockRequest) SetURI(uri string) {
	r.uri = uri
}

func (r *MockRequest) Body() api.Body {
	return r.body
}

func (r *MockRequest) GetProtocolVersion() string {
	return "HTTP/1.1"
}

func (r *MockRequest) GetSourceAddr() string {
	return r.sourceAddr
}

func (r *MockRequest) GetURI() string {
	return r.uri
}

func (r *MockRequest) Trailers() api.Header {
	return NewMockHeaders()
}

type MockResponse struct {
	headers    api.Header
	body       api.Body
	statusCode uint32
}

func NewMockResponse() *MockResponse {
	return &MockResponse{
		headers:    NewMockHeaders(),
		body:       NewMockBody(),
		statusCode: 200,
	}
}

func (r *MockResponse) Headers() api.Header {
	return r.headers
}

func (r *MockResponse) Body() api.Body {
	return r.body
}

func (r *MockResponse) SetStatusCode(code uint32) {
	r.statusCode = code
}

func (r *MockResponse) GetStatusCode() uint32 {
	return r.statusCode
}

func (r *MockResponse) Trailers() api.Header {
	return NewMockHeaders()
}

// MockAuthService ist ein Mock für den externen Authentifizierungsdienst
type MockAuthService struct {
	pb.UnimplementedAuthServiceServer
	allowAuth bool
	metadata  map[string]string
	message   string
}

// Authenticate implementiert die Authentifizierungslogik für Tests
func (m *MockAuthService) Authenticate(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	if m.allowAuth {
		return &pb.AuthResponse{
			Allowed:  true,
			Message:  m.message,
			Metadata: m.metadata,
		}, nil
	}
	return &pb.AuthResponse{
		Allowed: false,
		Message: "unauthorized",
	}, nil
}
