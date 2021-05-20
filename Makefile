#!/bin/sh

# build targets
tcpsplice: static.go *.go
	@env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath -o tcpsplice
	@-strip tcpsplice 2>/dev/null || true
	@-#upx -9 tcpsplice 2>/dev/null || true
static.go: rpack static/*
	@-./rpack static
rpack:
	@-env GOBIN=`pwd` go get github.com/pyke369/golang-support/rpack/rpack
clean:
distclean:
	@rm -f tcpsplice *.upx static.go rpack
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../tcpsplice_*

# run targets
run: tcpsplice
	@./tcpsplice conf/tcpsplice.conf
