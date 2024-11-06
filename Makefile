.PHONY: lint test vendor clean proto install-proto-deps

export GO111MODULE=on

default: lint test

# Protoc parameters
PROTOC=protoc
PROTO_DIR=proto
PROTO_FILES=$(PROTO_DIR)/*.proto

# Install protoc dependencies
install-proto-deps:
	go get github.com/golang/protobuf/protoc-gen-go

# Generate proto files
proto: install-proto-deps
	$(PROTOC) --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)

lint:
	golangci-lint run

test: proto
	go test -v -cover -timeout 30s ./...

yaegi_test:
	yaegi test -v .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
	rm -f $(PROTO_DIR)/*.pb.go

generate-certs:
	# Create CA key and certificate
	openssl genpkey -algorithm RSA -out certs/dummy-ca.key -pkeyopt rsa_keygen_bits:2048
	openssl req -x509 -new -nodes -key certs/dummy-ca.key -sha256 -days 365 -out certs/dummy-ca.crt -subj "/C=DE/ST=Some-State/L=Locality/O=Organization/OU=OrgUnit/CN=CA"

	# Create server key and certificate signing request (CSR)
	openssl genpkey -algorithm RSA -out certs/dummy-server.key -pkeyopt rsa_keygen_bits:2048
	openssl req -new -key certs/dummy-server.key -out certs/dummy-server.csr -config certs/openssl.cnf

	# Sign server certificate with CA
	openssl x509 -req -in certs/dummy-server.csr -CA certs/dummy-ca.crt -CAkey certs/dummy-ca.key -CAcreateserial -out certs/dummy-server.crt -days 365 -sha256 -extfile certs/openssl.cnf -extensions v3_ca

	# Clean up CSR and serial files
	rm -f certs/dummy-server.csr certs/dummy-ca.srl