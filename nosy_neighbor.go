package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	nt "github.com/infosecual/nosy/src/types"
)

// global config
var TargetConfig nt.TargetRepoConfig
var FuzzFunctions []string

// default help menu
func print_help_menu() {
	fmt.Println("Please provide an action and a target YAML file")
	fmt.Println("Actions:")
	fmt.Println("\t--init\t\t\tintialize a target environmnet")
	fmt.Println("\t--generate-harness\tgenerate fuzz harnesses for the target")
	fmt.Println("\t--fuzz\t\t\tfuzz the target")
	fmt.Println("")
	fmt.Println("Example usage:")
	fmt.Println("\t# This will download the target repo")
	fmt.Println("\tgo run . --init target_configs/example_source.yaml")
	fmt.Println("")
	fmt.Println("\t# This will parse the target source and gerenate")
	fmt.Println("\t# the fuzz harnesses")
	fmt.Println("\tgo run . --generate-harness target_configs/example_source.yaml")
	fmt.Println("")
	fmt.Println("\t# This will build the fuzzers and begin fuzzing the target")
	fmt.Println("\t# in a docker container")
	fmt.Println("\tgo run . --fuzz target_configs/example_source.yaml")
	fmt.Println("")
}

func generate_harness_gen_script(output_dir string) {
	script := "go get github.com/infosecual/go-fuzz-fill-utils/fuzzer\n"
	script += "go get github.com/trailofbits/go-fuzz-utils\n"
	script += "go get github.com/infosecual/nosy/src/types\n"

	// add any deps for target package harness_generation
	for _, dep := range TargetConfig.HarnessGenDeps {
		script += dep
		script += "\n"
	}

	script += fmt.Sprintf("%s run /src/cmd/parse-package/*.go\n", TargetConfig.TargetGoVersion)

	// write the script to the atargets /src dir
	f, err := os.Create(fmt.Sprintf("%s/gen_harness.sh", output_dir))
	if err != nil {
		log.Fatal(err)
	}
	_, err = f.WriteString(script)
	f.Close()

}

func copy_source_parsers_and_configs(target_dir string) {
	// get pwd for subsequent commands
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	// emit shell script for harness generation
	src_dir := pwd + "/src"
	generate_harness_gen_script(src_dir)

	// copy parsing routines to target's container
	fmt.Println("\nCopying parsing routines and config to target's assets directory")
	cmd := fmt.Sprintf("cp -r %s %s", src_dir, target_dir)
	exec_and_print(cmd)

	// copy target config file to target's container
	config_path := os.Args[2]
	cmd = fmt.Sprintf("cp %s %s", config_path, target_dir+"/src/config.yaml")
	exec_and_print(cmd)
}

func generate_init_script(target_dir string) {
	fmt.Println("\nGeneratng target's initilization script:")
	fmt.Println()
	script := fmt.Sprintf("REPO_URL=\"%s\"\n", TargetConfig.TargetRepoURL)
	script += fmt.Sprintf("BRANCH=\"%s\"\n", TargetConfig.TargetRepoBranch)
	script += fmt.Sprintf("REPO_PREFIX=\"%s\"\n", TargetConfig.TargetRepoImportPrefix)
	script += `rm /go/src/github/* -rf
mkdir -p /go/src/$REPO_PREFIX/nosy_fuzz_dir
mkdir /temp
git clone -b $BRANCH $REPO_URL /temp
mv /temp/* /go/src/$REPO_PREFIX
cd /go/src/$REPO_PREFIX
go get -t -d ./...
cp /go /staging -rp
# this is an interesting way to get around the fact that we cannot add our
# harness into the intialized target repo because its perms are restrictive
# to root:root (we make a user and group with your name in the container,
# chown everything to it)
groupadd user
useradd -s /bin/bash -d / -m -g user user
chown user -R /staging
chmod -R u+w /staging
`
	fmt.Print(script)
	fmt.Println()
	f, err := os.Create(fmt.Sprintf("%s/init_target.sh", target_dir))
	if err != nil {
		log.Fatal(err)
	}
	_, err = f.WriteString(script)
	f.Close()
}

func generate_fuzz_script(target_dir string, docker_repo_path string) {
	fmt.Println("\nGenerating target's fuzzing script:")
	fmt.Println()

	script := ""
	seconds := TargetConfig.TestTimeSeconds
	for i := 0; i < len(FuzzFunctions)/2; i++ {
		script += fmt.Sprintf("echo \"Fuzzing function %s for %d seconds\"\n", FuzzFunctions[2*i], seconds)
		script += fmt.Sprintf("cd %s\n", FuzzFunctions[2*i+1])
		script += fmt.Sprintf("%s test -fuzz=%s -fuzztime=%ds\n", TargetConfig.TargetGoVersion, FuzzFunctions[2*i], seconds)
		script += fmt.Sprintf("if [ -d \"./testdata/fuzz\" ]; then\n")
		script += fmt.Sprintf("\tmv ./testdata/fuzz/* %s/nosy_fuzz_dir/\n", docker_repo_path)
		script += fmt.Sprintf("\trm -rf ./testdata/fuzz/*\n")
		script += fmt.Sprintf("\techo \"cd %s && go test -run=%s/nosy_fuzz_dir/%s/.\"\n", FuzzFunctions[2*i+1], docker_repo_path, FuzzFunctions[2*i])
		script += fmt.Sprintf("fi\n")
	}
	f, err := os.Create(fmt.Sprintf("%s/nosy_fuzz_dir/fuzz_target.sh", target_dir))
	if err != nil {
		log.Fatal(err)
	}
	_, err = f.WriteString(script)
	f.Close()
}

func exec_and_print(command string) {
	fmt.Println(command)
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// --init will download and initialize the target repo to fuzz
func init_target() {
	fmt.Println("Initalizing target repo...")
	fmt.Println("\tName: ", TargetConfig.TargetRepo)
	fmt.Println("\tURL: ", TargetConfig.TargetRepoURL)
	fmt.Println("\tBranch: ", TargetConfig.TargetRepoBranch)
	fmt.Println()
	fmt.Println("Creating docker container for target...")
	fmt.Println()

	// build docker image
	command := fmt.Sprintf("BUILDKIT=1 docker build -t nosy-neighbor -f nosy-fuzzer.Dockerfile .")
	exec_and_print(command)

	// get pwd for subsequent commands
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	// target directory is where all shared files, scripts, test corpora
	// (all assets) for the fuzzing container will live
	target_dir := fmt.Sprintf("%s/fuzzing_directory/%s", pwd, TargetConfig.TargetRepo)

	// docker will write files as root so we should die here if the file exists
	// as we will get permission errors
	if _, err := os.Stat(target_dir); !os.IsNotExist(err) {
		fmt.Println("Target directory already exists, removing it...")
		//fmt.Printf("Please run:\n\tsudo rm -rf %s\n", target_dir)
		//log.Fatal("Please remove the previous directory before initilizing a new target.")
		command = fmt.Sprintf("rm -rf %s", target_dir)
		exec_and_print(command)
	}

	// create the target's asset directory
	fmt.Printf("\nCreating target asset directory @ %s\n", target_dir)
	fmt.Println()
	command = fmt.Sprintf("mkdir -p %s", target_dir)
	exec_and_print(command)

	// generate and populate target's init script in the targets asset folder
	generate_init_script(target_dir)

	// run a the initilization scripts in the target container
	fmt.Println("\nRunning initilization scripts in target container...")
	fmt.Println()
	command = fmt.Sprintf("docker run -v %s:/staging nosy-neighbor /staging/init_target.sh", target_dir)
	exec_and_print(command)
}

func generate_fuzz_harnesses() {
	// get pwd for subsequent commands
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	// target directory is where all shared files, scripts, corpora,
	// container (all assets) for the fuzzing container will live
	target_dir := fmt.Sprintf("%s/fuzzing_directory/%s", pwd, TargetConfig.TargetRepo)

	// copy source parsing routines into docker image
	copy_source_parsers_and_configs(target_dir)

	// this is the to $GOROOT in the docker container
	local_goroot_path := fmt.Sprintf("%s/fuzzing_directory/%s/go",
		pwd,
		TargetConfig.TargetRepo)

	local_src_path := fmt.Sprintf("%s/fuzzing_directory/%s/src",
		pwd,
		TargetConfig.TargetRepo)

	// this is the path within the docker container that contains the binded
	// (mounted) target repo
	docker_repo_path := fmt.Sprintf("/go/src/%s",
		TargetConfig.TargetRepoImportPrefix)

	fmt.Println()
	fmt.Println("Source parsing dependencies have been added to the targets asset directory.")
	fmt.Println("Please run the following command:\n")
	fmt.Printf("docker run -it --workdir %s/ -v %s:/go -v %s:/src nosy-neighbor /src/gen_harness.sh\n",
		docker_repo_path, local_goroot_path, local_src_path)
	fmt.Println()

}

func fuzz() {

	// get pwd for subsequent commands
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	// get the path that we should place the fuzzers shell script in
	// this must be the absolute path for docker dir binding
	local_repo_path := fmt.Sprintf("%s/fuzzing_directory/%s/go/src/%s",
		pwd,
		TargetConfig.TargetRepo,
		TargetConfig.TargetRepoImportPrefix)

	// this is the to $GOROOT in the docker container
	local_goroot_path := fmt.Sprintf("%s/fuzzing_directory/%s/go",
		pwd,
		TargetConfig.TargetRepo)

	// this is the path within the docker container that contains the binded
	// (mounted) target repo
	docker_repo_path := fmt.Sprintf("/go/src/%s",
		TargetConfig.TargetRepoImportPrefix)

	// read in function to fuzz
	file, err := os.Open(local_repo_path + "/" + "fuzzable.txt")
	if err != nil {
		log.Fatal(err)
	}

	// scan the fuzzable text file to create a list of functions to fuzz
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		FuzzFunctions = append(FuzzFunctions, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	generate_fuzz_script(local_repo_path, docker_repo_path)

	fmt.Println("Fuzzing", len(FuzzFunctions)/2, "functions...")

	fmt.Println("To begin fuzzing please run the following commands:")
	fmt.Println()
	fmt.Printf("docker run -it --workdir %s/nosy_fuzz_dir -v %s:/go nosy-neighbor\n", docker_repo_path, local_goroot_path)
	fmt.Println("chmod 755 fuzz_target.sh && ./fuzz_target.sh | tee fuzzing.out")
}

func main() {
	// print help menu if invalid arguments
	if len(os.Args[1:]) < 2 {
		print_help_menu()
		return
	}

	// verify YAML config file format
	if strings.HasSuffix(os.Args[2], ".yaml") {
		TargetConfig = nt.ParseTargetConfig(os.Args[2])
	} else {
		fmt.Println("The target config must be a YAML file (.yaml)")
		return
	}

	// init subcommand
	if os.Args[1] == "--init" {
		init_target()
		return
	} else if os.Args[1] == "--generate-harness" {
		generate_fuzz_harnesses()
		return
	} else if os.Args[1] == "--fuzz" {
		fuzz()
		//fmt.Println("unimplemented")
		return
	} else {
		fmt.Println("unknown action: ", os.Args[1])
		return
	}
}
