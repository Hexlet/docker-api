OPENAPI_V2_URL ?= https://raw.githubusercontent.com/moby/moby/master/api/swagger.yaml
OPENAPI_V2_FILE ?= tmp/swagger-v2.yaml
OPENAPI_V3_FILE ?= tmp/openapi-v3.yaml
GOENV_OPENAPI = GOCACHE=$(CURDIR)/.cache/go-build GOMODCACHE=$(CURDIR)/.cache/go-mod GOPATH=$(CURDIR)/.cache/go GOSUMDB=off

.PHONY: openapi-convert-2to3

process: download convert

download:
	@echo "Downloading OpenAPI 2.0 spec from $(OPENAPI_V2_URL)"
	@curl -fsSL "$(OPENAPI_V2_URL)" -o "$(OPENAPI_V2_FILE)"

convert:
	@mkdir -p tmp
	@echo "Converting $(OPENAPI_V2_FILE) -> $(OPENAPI_V3_FILE)"
	@mkdir -p .cache/go-build .cache/go-mod .cache/go
	@cd tools/openapi2to3 && $(GOENV_OPENAPI) go run . ../../$(OPENAPI_V2_FILE) ../../$(OPENAPI_V3_FILE)
	@echo "Done: $(OPENAPI_V3_FILE)"

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

