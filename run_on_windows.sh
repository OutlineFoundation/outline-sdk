#!/bin/bash

# Copyright 2025 The Outline Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Runs a Windows binary on a remote Windows host via SSH.
# Requires OpenSSH server to be enabled on the Windows machine.
# Set WINDOWS_HOST to the SSH target (e.g. user@192.168.1.100).
#
# Usage:
#   WINDOWS_HOST=user@host go run -C x -exec "$(pwd)/run_on_windows.sh" ./...
#   WINDOWS_HOST=user@host go test -C x -exec "$(pwd)/run_on_windows.sh" ./...

set -eu

function main() {
  declare -r host_bin="$1"
  shift 1

  declare -r windows_host="${WINDOWS_HOST:?Set WINDOWS_HOST to the Windows SSH target (e.g. user@192.168.1.100)}"

  # Create a temporary directory on the Windows host
  declare -r windows_run_dir="$(ssh "${windows_host}" 'powershell -Command "(New-Item -ItemType Directory (Join-Path $env:TEMP (\"outline_\" + [Guid]::NewGuid().ToString(\"N\").Substring(0,8)))).FullName"')"
  trap "ssh '${windows_host}' powershell -Command \"Remove-Item -Recurse -Force '${windows_run_dir}'\"" EXIT

  declare -r basename="$(basename "${host_bin}")"
  # SCP requires forward slashes in the path
  declare -r windows_run_dir_fwd="${windows_run_dir//\\//}"
  scp "${host_bin}" "${windows_host}:${windows_run_dir_fwd}/${basename}"

  # Copy testdata directory if running tests
  declare -r testdata_dir="$(pwd)/testdata"
  if [[ "${host_bin##*.}" = "test" && -d "${testdata_dir}" ]]; then
    scp -r "${testdata_dir}" "${windows_host}:${windows_run_dir_fwd}/testdata"
  fi

  # Run the binary on the Windows host
  # shellcheck disable=SC2029
  ssh "${windows_host}" "cd '${windows_run_dir}' && '.\\${basename}' $*"
}

main "$@"
