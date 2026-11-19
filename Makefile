COMPOSE ?= docker compose

logdirs: ## make the bind-mounted log dirs writable by the container users
	@mkdir -p logs/app logs/waf
	@chmod 0777 logs/app logs/waf 2>/dev/null || true

up: logdirs ## build and start the stack
	$(COMPOSE) up -d --build
	@echo "storefront: http://localhost:8080/  (or http://<vm-ip>:8080/)"

down: ## stop the stack, keep logs
	$(COMPOSE) down

reset: logdirs ## rebuild clean and clear the security logs
	$(COMPOSE) down -v
	@# remove, do not truncate: a truncated file keeps host ownership and the
	@# WAF (nginx uid 101) cannot write it. Removed, the containers recreate it
	@# writable in the 0777 dir.
	@rm -f logs/app/security.ndjson logs/waf/audit.json 2>/dev/null || true
	$(COMPOSE) up -d --build

ps: ; $(COMPOSE) ps
logs: ; $(COMPOSE) logs -f --tail=50
app-log: ; @tail -n 50 -f logs/app/security.ndjson
waf-log: ; @tail -n 50 -f logs/waf/audit.json

test: ## run every module's detection test
	bash tests/run.sh

.PHONY: up down reset ps logs app-log waf-log test
