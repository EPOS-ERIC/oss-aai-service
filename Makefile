APP_NAME := oss-aaai
BIN_DIR := bin

.PHONY: run build test fmt tidy clean

run:
	go run .

build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(APP_NAME) .

test:
	go test ./...

fmt:
	gofmt -w *.go

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR)
