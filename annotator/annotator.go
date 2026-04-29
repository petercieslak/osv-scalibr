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

// Package annotator provides the interface for annotation plugins.
package annotator

import (
	"context"
	"os"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Annotator is the interface for an annotation plugin, used to add additional
// information to scan results such as VEX statements. Annotators have access to
// the filesystem but should ideally not query any external APIs. If you need to
// modify the scan results based on the output of network calls you should use
// the Enricher interface instead.
type Annotator interface {
	plugin.Plugin
	// Annotate annotates the scan results with additional information.
	Annotate(ctx context.Context, input *ScanInput, results *inventory.Inventory) error
}

// Config stores the config settings for the annotation run.
type Config struct {
	Annotators []Annotator
	ScanRoot   *scalibrfs.ScanRoot
}

// ScanInput provides information for the annotator about the scan.
type ScanInput struct {
	// The root of the artifact being scanned.
	ScanRoot *scalibrfs.ScanRoot
}

// Run runs the specified annotators on the scan results and returns their statuses.
func Run(ctx context.Context, config *Config, inventory *inventory.Inventory) ([]*plugin.Status, error) {
	var statuses []*plugin.Status
	if len(config.Annotators) == 0 {
		return statuses, nil
	}

	input := &ScanInput{
		ScanRoot: config.ScanRoot,
	}

	// This is required to prevent passing packages from embedded filesystems to
	// plugins that issue commands on packages.
	//
	// Some annotator plugins require the system to be in a running state to perform
	// tasks such as executing commands or running binaries on the target filesystem.
	// Embedded filesystems, however, are not mounted as live systems; they are
	// extracted to the local filesystem for analysis by Scalibr.
	//
	// This is particularly important when the embedded filesystem contains binaries
	// for an architecture different from the one Scalibr is currently running on,
	// since emulation is not currently supported.
	//
	// Therefore, packages originating from embedded filesystems are filtered out and
	// not supplied to plugins that require a running system.
	filteredInventory := filterOutEmbeddedPackages(inventory)

	for _, a := range config.Annotators {
		var err error

		if !a.Requirements().RunningSystem {
			err = a.Annotate(ctx, input, inventory)
		} else {
			err = a.Annotate(ctx, input, filteredInventory)
		}

		statuses = append(statuses, plugin.StatusFromErr(a, false, err, nil))
	}
	return statuses, nil
}

func filterOutEmbeddedPackages(inv *inventory.Inventory) *inventory.Inventory {
	if inv == nil {
		return &inventory.Inventory{}
	}
	filtered := *inv // shallow copy

	var pkgs []*extractor.Package
	for _, p := range inv.Packages {
		if !isPackageFromEmbeddedFS(p) {
			pkgs = append(pkgs, p)
		}
	}

	filtered.Packages = pkgs
	return &filtered
}

// isPackageFromEmbeddedFS returns true if the package originates from an embedded filesystem.
func isPackageFromEmbeddedFS(pkg *extractor.Package) bool {
	location := pkg.Location.PathOrEmpty()
	if location == "" {
		return false
	}

	parts := strings.Split(location, ":")

	// Windows: skip drive letter (e.g., "C:\")
	if os.PathSeparator == '\\' {
		return len(parts) >= 3
	}

	// Linux/macOS: embedded FS typically has at least one ":" separator
	return len(parts) >= 2
}
