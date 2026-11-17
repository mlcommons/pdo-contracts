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

# Graph mode without a ledger: the graph combinators on OPA and on regorus, and the vectors of
# every graph in test/graphs/ through the reference implementation.
# Needs opa, and python3 with the regorus bindings (pdo/rego/graph/engine.py).
set -e
cd "$(dirname "$0")/.."
export PYTHONPATH=$PWD

opa test pdo/rego/graph test/combinators
python3 test/combinators/run_tests.py
for graph in test/graphs/*/graph.json; do
    folder=$(dirname "$graph")
    python3 -m pdo.rego.graph.cli eval --graph "$graph" --components "$folder/components" \
        --vectors "$folder/graph_vectors.json"
done
