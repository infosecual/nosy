# Nosy Neighbor
## Just "Nosy"
Nosy Neighbor is a horribly named project so we will call it "nosy" from here on out.
## What is it?
Nosy is a project designed to automatically create fuzzing harnesses for golang projects. It is a security research project and is not designed with any warranty. It is the source parsing section is currently in its third version. V1 was python, V2 used go/parser AST feng shui, and v3 copies a bunch of code from the fzgen project (https://github.com/thepudds/fzgen) because their methodologies where way better than mine.
## Dependencies
Nosy uses docker to isolate the target build and run environments. This helps significantly with dependency managements and provides a simple way to jail the target so that fuzzing does not pulverize the host's file system or lock up all network sockets for example. If you do not have docker installed you can find instructions [here](https://docs.docker.com/engine/install/ubuntu/).
## How to use
To use the tool refer to the cli's help menu:
```
➜  nosy git:(main) ✗ go run .
Please provide an action and a target YAML file
Actions:
	--init			initialize a target environment
	--generate-harness	generate fuzz harnesses for the target
	--fuzz			fuzz the target

Example usage:
	# This will download the target repo
	go run . --init target_configs/example_source.yaml

	# This will parse the target source and generate
	# the fuzz harnesses
	go run . --generate-harness target_configs/example_source.yaml

	# This will build the fuzzers and begin fuzzing the target
	# in a docker container
	go run . --fuzz target_configs/example_source.yaml
```
## More to come
Nosy is a work in progress and someday I will update it trophy case and add more info here. Today is not that day. Have fun fuzzing :)