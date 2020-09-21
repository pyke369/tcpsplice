#!/bin/sh

tcpsplice: *.go monitor.html
	@(echo -n "package main\nimport \"encoding/base64\"\nconst _monitorContent = \""; base64 -w 0 < monitor.html; echo "\"\nvar monitorContent []byte\nfunc init() { monitorContent, _ = base64.StdEncoding.DecodeString(_monitorContent) }") >monitor.go
	@export GOPATH=/tmp/go; export CGO_ENABLED=0; go build -trimpath -o tcpsplice && strip tcpsplice
clean:
distclean:
	@rm -rf tcpsplice monitor.go
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../tcpsplice_*

run: tcpsplice
	@./tcpsplice tcpsplice.conf
