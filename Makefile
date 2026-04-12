# IronWall-WAF — Test Runner
# Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com

.PHONY: test test-e2e test-unit test-bench test-race lint coverage clean

# ── Unit Tests (all modules) ──────────────────────────────────────────────────
test-unit:
	@echo "🧪 Running unit tests..."
	cd licensing && go test ./... -v -timeout 60s
	@echo "✅ Unit tests complete"

# ── E2E Integration Tests ─────────────────────────────────────────────────────
test-e2e:
	@echo "🔗 Running E2E integration tests..."
	cd tests/e2e && go test ./suites/... -v -timeout 120s -count=1
	@echo "✅ E2E tests complete"

# ── All Tests ─────────────────────────────────────────────────────────────────
test: test-unit test-e2e
	@echo "✅ All tests passed"

# ── Race Condition Detection ──────────────────────────────────────────────────
test-race:
	@echo "🏁 Running race detector tests..."
	cd licensing && go test ./... -race -timeout 60s
	cd tests/e2e && go test ./suites/... -race -timeout 120s
	@echo "✅ Race tests complete"

# ── Benchmarks ────────────────────────────────────────────────────────────────
test-bench:
	@echo "⚡ Running benchmarks..."
	cd tests/e2e && go test ./suites/... -bench=. -benchmem -run=^$$ -benchtime=3s
	@echo "✅ Benchmarks complete"

# ── Code Coverage ─────────────────────────────────────────────────────────────
coverage:
	@echo "📊 Generating coverage report..."
	cd licensing && go test ./... -coverprofile=coverage.out -covermode=atomic
	cd licensing && go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report: licensing/coverage.html"

# ── Lint ──────────────────────────────────────────────────────────────────────
lint:
	@echo "🔍 Running linters..."
	cd licensing && golangci-lint run ./...
	cd premium/zerodayshield && golangci-lint run ./... || true
	cd premium/ddos && golangci-lint run ./... || true
	@echo "✅ Lint complete"

# ── Security Scan ─────────────────────────────────────────────────────────────
security:
	@echo "🔒 Running security scan..."
	trivy fs . --severity HIGH,CRITICAL --format table
	@echo "✅ Security scan complete"

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	find . -name "coverage.out" -o -name "coverage.html" | xargs rm -f
	find . -name "*.test" | xargs rm -f
	@echo "✅ Clean complete"

# ── Quick smoke test (no deps needed) ────────────────────────────────────────
smoke:
	@echo "💨 Smoke test — license key format validation..."
	cd licensing && go test ./... -run TestKeyFormat -v
	@echo "✅ Smoke test passed"

# ── CI target ─────────────────────────────────────────────────────────────────
ci: lint test coverage security
	@echo "✅ CI pipeline complete"
