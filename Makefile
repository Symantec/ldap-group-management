# Go parameters

GOPATH ?= $(HOME)/go

#This is how we want to name the binary output
BINARY=smallpoint

# These are the values we want to pass for Version and BuildTime
VERSION=0.1.2

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

${BINARY}-${VERSION}.tar.gz:
	mkdir ${BINARY}-${VERSION}
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" lib/ ${BINARY}-${VERSION}/lib/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" cmd/ ${BINARY}-${VERSION}/cmd/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" misc/ ${BINARY}-${VERSION}/misc/
	cp LICENSE Makefile smallpoint.spec README.md ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/

rpm:	${BINARY}-${VERSION}.tar.gz
	rpmbuild -ta ${BINARY}-${VERSION}.tar.gz

tar:	${BINARY}-${VERSION}.tar.gz
