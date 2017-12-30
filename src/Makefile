ifeq ($(origin VERSION), undefined)
  VERSION=$(git rev-parse --short HEAD)
endif

GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)
REPOPATH = kubernetes-ldap

build: dependencies
	go build -o bin/kubernetes-ldap -ldflags "-X $(REPOPATH).Version=$(VERSION)" ./cmd/kubernetes-ldap.go

run:
	./bin/kubernetes-ldap

dependencies:
	go get github.com/go-ldap/ldap
	go get github.com/golang/glog
	go get github.com/spf13/pflag
	go get gopkg.in/square/go-jose.v2