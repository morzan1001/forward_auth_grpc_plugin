.PHONY: lint test vendor clean proto install-proto-deps

export GO111MODULE=on

default: lint test

# Protoc parameters
PROTOC=protoc
PROTO_DIR=proto
PROTO_FILES=$(PROTO_DIR)/*.proto

# Install protoc dependencies
install-proto-deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

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