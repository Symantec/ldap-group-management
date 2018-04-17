# Go parameters

GOPATH ?= $(HOME)/go

all: test build

build:
	cd $(GOPATH)/src; go install  github.com/Symantec/ldap-group-management/cmd/*

test:
	go test -v ./...

clean:
	go clean
	rm -f $(BINARY_NAME)

deps:
	go get -t ./...
