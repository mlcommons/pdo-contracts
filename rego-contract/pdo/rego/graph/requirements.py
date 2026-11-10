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

"""The requirement alternatives of a policy graph, as set_policy_graph expands them. Needs
no Rego engine, so a client can compute them from the components' interfaces alone."""

MAX_ALTERNATIVES = 64


class GraphError(Exception):
    pass


def _minimal(bundles):
    unique = set(bundles)
    return [b for b in unique if not any(other < b for other in unique)]


def _product(left, right):
    out = _minimal([a | b for a in left for b in right])
    if len(out) > MAX_ALTERNATIVES:
        raise GraphError(f"the graph has more than {MAX_ALTERNATIVES} requirement alternatives")
    return out


def _bundle_key(bundle):
    return (len(bundle), sorted(f"{role}\0{type}" for role, type in bundle))


def alternatives(graph, interfaces):
    """The requirement alternatives: each a minimal set of presented credential types, by role,
    smallest first. A node input needs its producer's requirements; accept_presented adds the
    alternative of presenting that credential instead."""
    memo = {}

    def node_alternatives(n):
        if n not in memo:
            node = graph["nodes"][n]
            alts = [frozenset()]
            for name in sorted(node["inputs"]):
                alts = _product(alts, input_alternatives(node, name))
            memo[n] = alts
        return memo[n]

    def input_alternatives(node, name):
        spec = interfaces[node["component"]]["inputs"][name]
        own = [frozenset([(spec["role"], spec["type"])])]
        raw = node["inputs"][name]
        alts = [frozenset()]
        for source in raw if isinstance(raw, list) else [raw]:
            if source["from"] == "presented":
                options = own
            elif source["accept_presented"]:
                options = _minimal(own + node_alternatives(source["node"]))
            else:
                options = node_alternatives(source["node"])
            alts = _product(alts, options)
        return alts

    out = []
    for bundle in sorted(node_alternatives(graph["root"]), key=_bundle_key):
        by_role = {}
        for role, type in bundle:
            by_role.setdefault(role, []).append(type)
        out.append({role: sorted(types) for role, types in sorted(by_role.items())})
    return out


def roles(graph, interfaces):
    """Every role some alternative presents from."""
    return sorted({role for bundle in alternatives(graph, interfaces) for role in bundle})
