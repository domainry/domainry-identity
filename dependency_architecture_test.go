package main

import (
	"os"
	"strings"
	"testing"
)

func TestModuleUsesTaggedDependencies(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "replace ") || strings.Contains(string(content), "../domainry-") {
		t.Fatal("Identity must consume released module tags, not local directory replacements")
	}
}
