.PHONY: all dnsgw tunnelcli clean

DNSGW_BIN=dnsgw
TUNNELCLI_BIN=tunnelcli

GO=go

all: dnsgw tunnelcli

dnsgw:
	@echo "Building dnsgw..."
	$(GO) build -o $(DNSGW_BIN) .

tunnelcli:
	@echo "Building tunnelcli..."
	cd cli && $(GO) build -o ../$(TUNNELCLI_BIN) .

clean:
	@echo "Cleaning up..."
	rm -f $(DNSGW_BIN)
	rm -f $(TUNNELCLI_BIN)