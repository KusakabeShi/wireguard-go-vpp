PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go-vpp

wireguard-go-vpp: export CGO_CFLAGS ?= -I/usr/include/memif
wireguard-go-vpp: $(wildcard *.go) $(wildcard */*.go)
	go mod vendor && \
	patch -p0 -i govpp_remove_crcstring_check.patch && \
	go build -v -o "$@"

install: wireguard-go-vpp
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go-vpp"

test:
	go test -v ./...

clean:
	rm -f wireguard-go-vpp

.PHONY: all clean test install generate-version-and-build
