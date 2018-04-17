# Go parameters

<<<<<<< HEAD
GOPATH ?= $(HOME)/go
=======
BINARY_NAME=mybinary
>>>>>>> removedunnecessary code

all: test build

build:
<<<<<<< HEAD
	cd $(GOPATH)/src; go install  github.com/Symantec/ldap-group-management/cmd/*

test:
	go test -v ./...

clean:
	go clean
	rm -f $(BINARY_NAME)

deps:
	go get -t ./...
=======
	 go build -o $(BINARY_NAME) -v

test:
	 go test -v ./...

clean:
	 (GOCLEAN)
	rm -f $(BINARY_NAME)

run:
	 go build -o $(BINARY_NAME) -v ./...
	./$(BINARY_NAME)

deps:
	 go -t ./...
>>>>>>> removedunnecessary code
