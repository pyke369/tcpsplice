#!/bin/sh

tcpsplice: tcpsplice.go monitor.html
	@(echo -n "package main\nimport \"encoding/base64\"\nconst _monitorContent = \""; base64 -w 0 < monitor.html; echo "\"\nvar monitorContent []byte\nfunc init() { monitorContent, _ = base64.StdEncoding.DecodeString(_monitorContent) }") >monitor.go
	@export GOPATH=`pwd`; export GIT_SSL_NO_VERIFY=true; export CGO_ENABLED=0; go get -v -d && go build tcpsplice.go monitor.go && strip tcpsplice

run: tcpsplice
	@./tcpsplice tcpsplice.conf

deb:
	@debuild -i -us -uc -b

clean:

distclean:
	@rm -rf tcpsplice monitor.go src

debclean:
	@debuild clean
