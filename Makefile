OPENAPI_V2_URL ?= https://raw.githubusercontent.com/moby/moby/master/api/swagger.yaml
OPENAPI_V2_FILE ?= tmp/swagger-v2.yaml
BUILD_ID ?=

download:
	@echo "Downloading OpenAPI 2.0 spec from $(OPENAPI_V2_URL)"
	@curl -fsSL "$(OPENAPI_V2_URL)" -o "$(OPENAPI_V2_FILE)"

setup:
	pnpm install

update:
	npx ncu -u
	pnpm update

compile-openapi:
	pnpm exec tsp compile .

publish:
	stl builds create --branch main # --pull # --allow-empty 

build:
	stl builds create --branch main

build-ruby:
	stl builds create --branch main --target ruby

build-ruby-pull:
	stl builds create --branch main --target ruby --pull

build-diagnostics:
	test -n "$(BUILD_ID)" || (echo "Usage: make build-diagnostics BUILD_ID=bui_..." && exit 1)
	stl builds:diagnostics list --build-id $(BUILD_ID)

.PHONY: setup update compile-openapi publish build build-ruby build-ruby-pull build-diagnostics
