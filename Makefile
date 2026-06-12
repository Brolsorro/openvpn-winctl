.PHONY: build build-windows test lint clean

build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	go build -ldflags="-s -w" -o openvpn-manager.exe ./cmd/ovpn-manager

build:
	go build -ldflags="-s -w" -o openvpn-manager.exe ./cmd/ovpn-manager

test:
	go test ./internal/config/... ./internal/server/...

lint:
	golangci-lint run ./...

clean:
	rm -f openvpn-manager.exe
