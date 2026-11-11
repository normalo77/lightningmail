.PHONY: smoke smoke-down relay-build relay-test relay-vet relay-fmt relay-check

smoke:
	./test/smoke.sh
smoke-down:
	docker compose -p lightningmail-test -f test/docker/docker-compose.yml down

# Etappe 2a: Relay-Core (Go). Ziel-Präfix relay-*, Delegierung an relay/Makefile.
relay-build relay-test relay-vet relay-fmt:
	$(MAKE) -C relay $(@:relay-%=%)

relay-check: ## go vet + go test + gofmt-Check, wie im Erfolgskriterium
	$(MAKE) -C relay fmt-check vet test build
