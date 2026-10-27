// SPDX-License-Identifier: AGPL-3.0-only
// Generate only the Hello bindings from the exact published NuGet descriptor.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

type contractLock struct {
	Package          string `json:"package"`
	Version          string `json:"version"`
	SHA512           string `json:"sha512"`
	SourceCommit     string `json:"sourceCommit"`
	DescriptorSHA256 string `json:"descriptorSha256"`
	Schema           string `json:"schema"`
	SchemaSHA256     string `json:"schemaSha256"`
	GoPackage        string `json:"goPackage"`
}

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	var lock contractLock
	raw, err := os.ReadFile("contracts.lock.json")
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &lock); err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	packages := os.Getenv("NUGET_PACKAGES")
	if packages == "" {
		packages = filepath.Join(home, ".nuget", "packages")
	}
	directory := filepath.Join(packages, strings.ToLower(lock.Package), lock.Version)
	archive, err := os.ReadFile(filepath.Join(directory, strings.ToLower(lock.Package)+"."+lock.Version+".nupkg"))
	if err != nil {
		return fmt.Errorf("restore the pinned Contracts NuGet package first: %w", err)
	}
	sum := sha512.Sum512(archive)
	if base64.StdEncoding.EncodeToString(sum[:]) != lock.SHA512 {
		return fmt.Errorf("Contracts package SHA512 mismatch")
	}
	identityData, err := os.ReadFile(filepath.Join(directory, "source.json"))
	if err != nil {
		return err
	}
	var identity struct {
		Commit  string `json:"commit"`
		Version string `json:"version"`
		Dirty   bool   `json:"dirty"`
	}
	if err = json.Unmarshal(identityData, &identity); err != nil {
		return err
	}
	if identity.Commit != lock.SourceCommit || identity.Version != lock.Version || identity.Dirty {
		return fmt.Errorf("published Contracts identity mismatch")
	}
	descriptor, err := checkedFile(filepath.Join(directory, "contracts.binpb"), lock.DescriptorSHA256)
	if err != nil {
		return err
	}
	if _, err = checkedFile(filepath.Join(directory, "schemas", filepath.FromSlash(lock.Schema)), lock.SchemaSHA256); err != nil {
		return err
	}
	var set descriptorpb.FileDescriptorSet
	if err = proto.Unmarshal(descriptor, &set); err != nil {
		return err
	}
	const name = "arcforges/hello/v1/hello.proto"
	var hello *descriptorpb.FileDescriptorProto
	for _, file := range set.File {
		if file.GetName() == name {
			hello = file
			break
		}
	}
	if hello == nil || len(hello.Dependency) != 0 || hello.GetPackage() != "arcforges.hello.v1" {
		return fmt.Errorf("unexpected Hello descriptor or dependencies")
	}
	parameter := "paths=source_relative,M" + name + "=" + lock.GoPackage
	request, err := proto.Marshal(&pluginpb.CodeGeneratorRequest{
		FileToGenerate: []string{name}, ProtoFile: []*descriptorpb.FileDescriptorProto{hello},
		Parameter: proto.String(parameter),
	})
	if err != nil {
		return err
	}
	output := filepath.Join("internal", "gen")
	hashes := map[string]string{}
	for _, tool := range []string{"protoc-gen-go", "protoc-gen-connect-go"} {
		command := exec.Command("go", "tool", tool)
		command.Stdin = bytes.NewReader(request)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		result, err := command.Output()
		if err != nil {
			return fmt.Errorf("%s failed: %s", tool, stderr.String())
		}
		var response pluginpb.CodeGeneratorResponse
		if err = proto.Unmarshal(result, &response); err != nil {
			return err
		}
		if response.GetError() != "" {
			return fmt.Errorf("%s: %s", tool, response.GetError())
		}
		for _, file := range response.File {
			relative := file.GetName()
			if !strings.HasPrefix(relative, "arcforges/hello/v1/") || strings.Contains(relative, "..") ||
				strings.Contains(relative, "\\") || filepath.IsAbs(relative) || file.GetInsertionPoint() != "" {
				return fmt.Errorf("unsafe generated path")
			}
			target := filepath.Join(output, filepath.FromSlash(relative))
			if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if err = os.WriteFile(target, []byte(file.GetContent()), 0644); err != nil {
				return err
			}
			hash := sha256.Sum256([]byte(file.GetContent()))
			hashes[relative] = hex.EncodeToString(hash[:])
		}
	}
	receipt, err := json.MarshalIndent(map[string]any{
		"package": lock.Package, "version": lock.Version, "sourceCommit": lock.SourceCommit,
		"descriptorSha256": lock.DescriptorSHA256, "generated": hashes,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(output, "receipt.json"), append(receipt, '\n'), 0644); err != nil {
		return err
	}
	fmt.Printf("Generated %d Hello bindings from %s %s\n", len(hashes), lock.Package, lock.Version)
	return nil
}

func checkedFile(path, expected string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != expected {
		return nil, fmt.Errorf("published contract digest mismatch")
	}
	return data, nil
}
