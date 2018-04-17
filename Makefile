# Go parameters

BINARY_NAME=mybinary

all: test build

build:
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
	 go get -t ./...
