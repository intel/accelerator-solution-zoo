#!/usr/bin/python3

import subprocess

curr_commit_cmd = "git rev-parse HEAD^@ | tail -n 1"
clone_cmd = "git clone --recursive https://github.com/ccp-project/portus"
checkout_libccp_commit = "cd ./portus/integration_tests/libccp_integration/libccp && git fetch && git checkout {}"
run_integration_test = "cd ./portus && make libccp-integration"
clean_cmd = "rm -rf portus"

curr_commit = subprocess.check_output(curr_commit_cmd, shell=True).strip().decode('utf-8')
print("libccp commit", curr_commit)
print("===cloning portus===")
subprocess.check_call(clone_cmd, shell=True)
print("===checkout libccp commit===")
subprocess.check_call(checkout_libccp_commit.format(curr_commit), shell=True)
print("===run integration test===")
subprocess.check_call(run_integration_test, shell=True)
print("===clean up===")
subprocess.check_call(clean_cmd, shell=True)
