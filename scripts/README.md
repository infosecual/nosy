This directory is a placeholder for scripts for common workflows.

#### triage.sh

Bash script to triage crashes found by nosy. Takes a crash log as input and outputs a csv file containing fuzzer harness name that found the crash and the panic it resulted in.

Usage

```
$ ./triage.sh <PATH_TO_NOSY_CRASH_LOG> <PATH_TO_CSV>
```

Example

```
$./triage.sh prysm_crashes.out prysm_crashes.csv
```
