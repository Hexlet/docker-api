package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"sigs.k8s.io/yaml"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <openapi-v2-input> <openapi-v3-output>\n", os.Args[0])
		os.Exit(2)
	}

	inputPath := os.Args[1]
	outputPath := os.Args[2]

	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		fatalf("read input file %q: %v", inputPath, err)
	}

	jsonData, err := yaml.YAMLToJSON(inputData)
	if err != nil {
		fatalf("convert input YAML to JSON: %v", err)
	}

	var docV2 openapi2.T
	if err := json.Unmarshal(jsonData, &docV2); err != nil {
		fatalf("decode OpenAPI v2: %v", err)
	}

	docV3, err := openapi2conv.ToV3(&docV2)
	if err != nil {
		fatalf("convert v2 -> v3: %v", err)
	}

	outputData, err := yaml.Marshal(docV3)
	if err != nil {
		fatalf("encode OpenAPI v3 as YAML: %v", err)
	}

	if err := os.WriteFile(outputPath, outputData, 0o644); err != nil {
		fatalf("write output file %q: %v", outputPath, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
