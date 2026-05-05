// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gleamtoml extracts gleam.toml files for Gleam projects.
package gleamtoml

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the name of the Extractor.
	Name = "gleam/gleamtoml"
)

type gleamTomlFile struct {
	Dependencies    map[string]string `toml:"dependencies"`
	DevDependencies map[string]string `toml:"dev-dependencies"`
}

// Extractor extracts Gleam packages from gleam.toml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a gleam.toml file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "gleam.toml"
}

// Extract extracts packages from gleam.toml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var f gleamTomlFile
	if _, err := toml.NewDecoder(input.Reader).Decode(&f); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	loc := extractor.LocationFromPath(input.Path)
	packages := make([]*extractor.Package, 0, len(f.Dependencies)+len(f.DevDependencies))

	var err error
	packages, err = appendPackages(ctx, packages, f.Dependencies, loc)
	if err != nil {
		return inventory.Inventory{Packages: packages}, err
	}
	packages, err = appendPackages(ctx, packages, f.DevDependencies, loc)
	if err != nil {
		return inventory.Inventory{Packages: packages}, err
	}

	return inventory.Inventory{Packages: packages}, nil
}

func appendPackages(
	ctx context.Context,
	packages []*extractor.Package,
	deps map[string]string,
	loc extractor.PackageLocation,
) ([]*extractor.Package, error) {
	for name, version := range deps {
		if err := ctx.Err(); err != nil {
			return packages, fmt.Errorf("gleam/gleamtoml halted due to context error: %w", err)
		}
		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeHex,
			Location: loc,
		})
	}
	return packages, nil
}

var _ filesystem.Extractor = Extractor{}
