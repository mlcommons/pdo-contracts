#!/usr/bin/env python3
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

"""Run the graph combinator tests on regorus, the engine the contract embeds, as opa test
runs them on OPA: every test_ rule of every *_test.rego here must be true.

    python3 run_tests.py
"""

import re
import sys
from pathlib import Path

import regorus

HERE = Path(__file__).resolve().parent
COMBINATORS = HERE.parents[1] / "pdo" / "rego" / "graph"

engine = regorus.Engine()
for path in sorted(COMBINATORS.glob("*.rego")) + sorted(HERE.glob("*.rego")):
    engine.add_policy(path.name, path.read_text())

failed = 0
total = 0
for path in sorted(HERE.glob("*_test.rego")):
    source = path.read_text()
    package = re.search(r"^package (\S+)", source, re.M).group(1)
    for test in re.findall(r"^(test_\w+) if", source, re.M):
        total += 1
        try:
            ok = engine.eval_rule(f"data.{package}.{test}") is True
        except Exception as e:
            ok = False
            print(f"  {e}")
        failed += not ok
        print(("PASS " if ok else "FAIL ") + f"{package}.{test}")
print(f"{total - failed}/{total} passed on regorus")
sys.exit(1 if failed else 0)
