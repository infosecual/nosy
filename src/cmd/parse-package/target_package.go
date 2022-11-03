package main

import (
	"fmt"
	//"regexp"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type TargetPackage struct {
	RealPath           string
	Name               string
	ImportPath         string
	TargetFunctions    []TargetFunction
	TargetConstructors []TargetFunction
	//IsIncludable bool
}

// helper function for creating new TargetPackage objects
func NewTargetPackage(name string, real_path string, target_config TargetRepoConfig) TargetPackage {
	// fun string manipulation to turn paths into go import paths
	// eg. transform:
	// "./fuzzing_directory/prysm/go/src/github.com/prysmaticlabs/prysm/validator/db/db"
	// into:
	// "github.com/prysmaticlabs/prysm/validator/db"
	fuzz_dir_path_prefix := fmt.Sprintf("./fuzzing_directory/%s/go/src/", target_config)
	trimmed_path := strings.TrimPrefix(real_path, fuzz_dir_path_prefix)
	s := strings.Split(trimmed_path, "/")
	trimmed_path = strings.TrimSuffix(trimmed_path, s[len(s)-1])
	trimmed_path = strings.TrimSuffix(trimmed_path, "/")
	return TargetPackage{RealPath: real_path,
		Name:       name,
		ImportPath: trimmed_path}
}

// returns a truncated hash of the import path for uniqueness
func (pkg TargetPackage) UniqueID() string {
	unique_id := sha256.Sum256([]byte(pkg.ImportPath))
	return hex.EncodeToString(unique_id[:4])
}

func (pkg TargetPackage) GenerateHarnessPath() string {
	// hash the import path so that multiple packages with the same name do
	// have unique IDs and do not conflict
	unique_id := sha256.Sum256([]byte(pkg.ImportPath))

	// place the harnesses in the repo directory for building
	return fmt.Sprintf("Nosy_fuzz_%s_%s_test.go",
		pkg.Name,
		hex.EncodeToString(unique_id[:4]))
}

// checks target config to see if the package should be excluded
func (pkg TargetPackage) in_ignore_packages(target_config TargetRepoConfig) bool {
	for _, bad_package := range target_config.IgnorePackages {
		if strings.Contains(pkg.ImportPath, bad_package) {
			//fmt.Println(bad_package, " ", pkg.ImportPath)
			return true
		}
	}
	return false
}

// checks various things to see if we should exclude the package
func (pkg TargetPackage) IsIncludable(target_config TargetRepoConfig) bool {
	if pkg.in_ignore_packages(target_config) {
		return false
	}
	//TODO: find a away around this
	//if pkg.Name == "main" {
	//    return false
	//}
	//TODO: find a away around this
	//if pkg.Name == "internal" {
	//    return false
	//}

	// return false unless there is at least one includable function in the
	// package
	for _, function := range pkg.TargetFunctions {
		if function.IsIncludable(target_config) {
			return true
		}
	}
	return false
}

// pretty print TargetPackage for debugging purposes
func (pkg TargetPackage) Print() {
	fmt.Println("#################################################")
	fmt.Printf("# real path: \t %s\n", pkg.RealPath)
	fmt.Printf("# package: \t %s\n", pkg.Name)
	fmt.Printf("# import path: \t %s\n", pkg.ImportPath)

	// if the packages has target functions then print them
	if len(pkg.TargetFunctions) > 0 {
		for i, f := range pkg.TargetFunctions {
			if i == 0 {
				fmt.Printf("# functions: \t %s\n", f.Name)
			} else {
				fmt.Printf("# \t\t %s\n", f.Name)
			}
		}
	}

	fmt.Println("#################################################")
	fmt.Println()
	return
}
