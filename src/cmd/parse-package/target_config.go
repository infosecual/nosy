package main

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
)

type TargetRepoConfig struct {
	TargetRepo              string   `yaml:"target_repo_name"`
	TargetRepoURL           string   `yaml:"target_repo_url"`
	TargetRepoBranch        string   `yaml:"target_repo_branch"`
	TargetRepoImportPrefix  string   `yaml:"target_repo_import_prefix"`
	TargetModuleDeclaration string   `yaml:"target_mod_self_declaration"`
	TargetGoVersion         string   `yaml:"go_version"`
	HarnessGenDeps          []string `yaml:"harness_gen_deps"`
	IgnorePackages          []string `yaml:"ignore_packages"`
	IgnoreFunctions         []string `yaml:"ignore_functions"`
	IgnoreTypes             []string `yaml:"ignore_types"`
	//TODO:
	//substitute_packages:
	TestTimeSeconds int `yaml:"seconds_per_target_function"`
}

// parse YAML file with target configuration
func ParseTargetConfig(yaml_file string) TargetRepoConfig {
	data, err := ioutil.ReadFile(yaml_file)
	if err != nil {
		log.Fatal(err)
	}
	var target_config TargetRepoConfig
	if err := target_config.Parse(data); err != nil {
		log.Fatal(err)
	}
	return target_config
}

// YAML unmarshal
func (c *TargetRepoConfig) Parse(data []byte) error {
	return yaml.Unmarshal(data, c)
}
