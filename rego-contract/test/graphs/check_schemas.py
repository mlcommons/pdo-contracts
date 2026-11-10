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

"""Check the test graphs, their components' interfaces and the credentials their components
return against the JSON schemas in docs/schemas."""

import json
import sys
from pathlib import Path

import jsonschema

from pdo.rego.graph.policy_graph import interfaces_of, load_components
from pdo.rego.graph.vectors import run

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "docs" / "schemas"


def validator(name):
    schema = json.loads((SCHEMAS / name).read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


graph_schema = validator("policy_graph.schema.json")
interface_schema = validator("component_interface.schema.json")
credential_schema = validator("component_credential.schema.json")

checked = 0
for folder in sorted(p.parent for p in (ROOT / "test" / "graphs").glob("*/graph.json")):
    graph = json.loads((folder / "graph.json").read_text())
    graph_schema.validate(graph)
    components = load_components(graph, folder / "components")
    interfaces = interfaces_of(components)
    for iface in interfaces.values():
        interface_schema.validate(iface)
    suite = json.loads((folder / "graph_vectors.json").read_text())
    for _, _, _, result in run(graph, components, interfaces, suite):
        for creds in result["outputs"].values():
            for cred in creds:
                credential_schema.validate(cred)
    checked += 1
print(f"{checked} graph(s), their interfaces and their outputs match the schemas")
sys.exit(0 if checked else 1)
