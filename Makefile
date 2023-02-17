#!/bin/sh

# build targets
tcpsplice: resources.go *.go
	@env GOPATH=/tmp/go go get -d && env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath -o tcpsplice
	@-strip tcpsplice 2>/dev/null || true
	@-upx -9 tcpsplice 2>/dev/null || true
resources.go: rpack resources/*
	@-./rpack resources
rpack:
	@-go get github.com/pyke369/golang-support/rpack/cmd && env GOBIN=$$(pwd) go install github.com/pyke369/golang-support/rpack/cmd && mv cmd rpack
clean:
distclean:
	@rm -f tcpsplice *.upx resources.go rpack
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../tcpsplice_*

# run targets
run: tcpsplice
	@./tcpsplice conf/tcpsplice.conf
