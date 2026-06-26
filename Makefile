OPENAPI_V2_URL ?= https://raw.githubusercontent.com/moby/moby/master/api/swagger.yaml
OPENAPI_V2_FILE ?= tmp/swagger-v2.yaml

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
