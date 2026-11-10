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

"""pdo-rego-graph: check a policy graph the way the rego_policy_agent contract will.

    pdo-rego-graph validate     --graph graph.json --components DIR
    pdo-rego-graph requirements --graph graph.json --components DIR
    pdo-rego-graph eval         --graph graph.json --components DIR --vectors graph_vectors.json

DIR holds one <component id>/component.rego per component.
"""

import argparse
import json
import sys

from .policy_graph import alternatives, load_components, validate
from .vectors import run


def _load(args):
    with open(args.graph) as f:
        graph = json.load(f)
    components = load_components(graph, args.components)
    interfaces, problems = validate(graph, components)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    return graph, components, interfaces


def cmd_validate(args):
    _load(args)
    print("valid")


def cmd_requirements(args):
    graph, _, interfaces = _load(args)
    print(json.dumps(alternatives(graph, interfaces), indent=2))


def cmd_eval(args):
    graph, components, interfaces = _load(args)
    with open(args.vectors) as f:
        suite = json.load(f)
    failed = 0
    for vector, expected, got, _ in run(graph, components, interfaces, suite):
        ok = got == expected
        failed += not ok
        print(("PASS " if ok else "FAIL ") + vector["name"])
        if not ok:
            print("  expected " + json.dumps(expected, sort_keys=True))
            print("  got      " + json.dumps(got, sort_keys=True))
    print(f"{len(suite['vectors']) - failed}/{len(suite['vectors'])} vectors passed")
    sys.exit(1 if failed else 0)


def main():
    parser = argparse.ArgumentParser(prog="pdo-rego-graph", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name, fn, extra in (
        ("validate", cmd_validate, []),
        ("requirements", cmd_requirements, []),
        ("eval", cmd_eval, ["--vectors"]),
    ):
        sub = commands.add_parser(name)
        sub.add_argument("--graph", required=True, help="the policy graph (JSON)")
        sub.add_argument("--components", required=True, help="folder of <id>/component.rego")
        for option in extra:
            sub.add_argument(option, required=True, help="the graph's test vectors (JSON)")
        sub.set_defaults(fn=fn)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
