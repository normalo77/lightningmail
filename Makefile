.PHONY: smoke smoke-down relay-build relay-test relay-vet relay-fmt relay-check e2e

smoke:
	./test/smoke.sh
smoke-down:
	docker compose -p lightningmail-test -f test/docker/docker-compose.yml down

# Etappe 2a: Relay-Core (Go).
relay-build relay-test relay-vet relay-fmt:
	$(MAKE) -C relay $(@:relay-%=%)

relay-check:
	$(MAKE) -C relay fmt-check vet test build

# Etappe 3: E2E Portomail-Flow
e2e:
	./test/e2e.sh
