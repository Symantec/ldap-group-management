function buildDocker {
    cd $currentPath; docker build -t registry.acp.us-east-1.aws.symcpe.net/cc/experimental/oidcrp .
}

function buildBinaries {
    for GOOS in darwin linux; do
        for GOARCH in amd64; do
            mkdir -p bin/$GOOS-$GOARCH
            # CGO_ENABLED=0 is required for
            # https://stackoverflow.com/questions/34729748/installed-go-binary-not-found-in-path-on-alpine-linux-docker
            GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -v -ldflags "-s -w" -o bin/$GOOS-$GOARCH/smallpoint
         done
    done
}

#buildMocks
#buildUnitTests
buildBinaries
# buildWeb
# buildDocker

# rm -rf release/static
# cp -r static release
# cp Changes.txt release/Changes.txt
