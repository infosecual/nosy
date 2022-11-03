package main

// This is made to be compiled via "go build ." and used as a standalone
// executable. This is done to take advantage of the directory dependencies
// of the go build system and its corresponding packages library.

import (
	"fmt"
	"go/types"
	"log"

	"golang.org/x/tools/go/packages"
)

// global config
var TargetConfig TargetRepoConfig

// global target list
var Targets []TargetPackage

var FuzzTargets []string

func main() {
	// parse target config file
	TargetConfig = ParseTargetConfig("/src/config.yaml")

	cfg := &packages.Config{Mode: packages.NeedName |
		packages.NeedFiles |
		packages.NeedCompiledGoFiles |
		packages.NeedImports |
		packages.NeedTypes |
		packages.NeedSyntax |
		packages.NeedTypesInfo |
		packages.NeedTypesSizes}

	// load package info
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		log.Fatal(fmt.Sprintf("load: %v\n", err))
	}
	if packages.PrintErrors(pkgs) > 0 {
		log.Fatal("failing due to packages error")
	}

	// parse AST for each package declared
	for _, pkg := range pkgs {
		selected_pkg := NewTargetPackage(pkg.Name, pkg.PkgPath, TargetConfig)

		// We used to get this info via go/parser AST walking but go/types makes life easier.
		// This section is heavily influenced by fzgen project: github.com/thepudds/fzgen
		for id, obj := range pkg.TypesInfo.Defs {
			func_decl, ok := obj.(*types.Func)
			if ok {
				selected_function := TargetFunction{Name: id.Name, PackageName: pkg.Name, PackagePath: pkg.PkgPath, TypesFunc: func_decl}

				// Check to see if the function is a constructor or not
				if selected_function.IsConstructor() {
					selected_pkg.TargetConstructors = append(selected_pkg.TargetConstructors, selected_function)
				} else {
					// add target function to the package's list
					selected_pkg.TargetFunctions = append(selected_pkg.TargetFunctions, selected_function)
				}
			}
		}

		Targets = append(Targets, selected_pkg)
	}

	generate_harnesses()
}
