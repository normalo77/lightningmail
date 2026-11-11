.PHONY: smoke smoke-down
smoke:
	./test/smoke.sh
smoke-down:
	docker compose -p lightningmail-test -f test/docker/docker-compose.yml down
