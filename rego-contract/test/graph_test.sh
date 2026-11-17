#!/bin/bash
# Copyright 2026 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The graph combinators' tests without a ledger, on OPA and on regorus, the engine the
# contract embeds. Needs opa, and python3 with the regorus bindings (see test/README.md).
set -e
cd "$(dirname "$0")/.."

opa test src/rego/graph_validator.rego src/rego/graph_planner.rego test/combinators
python3 test/combinators/run_tests.py
