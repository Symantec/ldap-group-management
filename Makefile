# Go parameters

GOPATH ?= $(HOME)/go

#This is how we want to name the binary output
BINARY=smallpoint

# These are the values we want to pass for Version and BuildTime
VERSION=0.1.0

all: test build

build:
	cd $(GOPATH)/src; go install -ldflags "-X main.Version=${VERSION}" github.com/Symantec/ldap-group-management/cmd/*

test:
	go test -v ./...

clean:
	go clean
	rm -f $(BINARY_NAME)

deps:
	go get -t ./...
