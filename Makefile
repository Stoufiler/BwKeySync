BINARY_NAME=bwkeysync
INSTALL_PATH=/usr/local/bin

.PHONY: build clean install

build:
	CGO_ENABLED=1 CGO_LDFLAGS="-framework CoreFoundation -framework Security -framework SystemConfiguration" go build -o $(BINARY_NAME)

clean:
	rm -f $(BINARY_NAME)

install: build
	install -m 755 $(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)

uninstall:
	rm -f $(INSTALL_PATH)/$(BINARY_NAME)

.DEFAULT_GOAL := build
