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

"""The reference implementation of graph mode: what set_policy_graph and
issue_policy_credential do with a policy graph, in Python, for tests, card authors and
previews. It runs the contract's own validator and planner (graph_validator.rego,
graph_planner.rego) and the components on regorus. docs/policy_graph.md is the spec.
"""

from pathlib import Path

from .engine import RegoError, eval_rule, packages
from .requirements import GraphError, alternatives

HERE = Path(__file__).parent
VALIDATOR = (HERE / "graph_validator.rego").read_text()
PLANNER = (HERE / "graph_planner.rego").read_text()

# the contract's limits; it refuses a graph or a request past any of them
MAX_NODES = 32
MAX_COMPONENTS = 16
MAX_INPUTS = 8
MAX_CREDENTIALS = 64
MAX_SOURCE_BYTES = 64 * 1024

KEY_TYPES = ("ec", "rsa")


def component_package(component_id):
    return f"data.pf.components.{component_id}"


def load_components(graph, directory):
    """``[[component id, source], ...]`` for the components the graph's nodes use, read from
    ``<directory>/<id>/component.rego``, sorted by id."""
    used = sorted({node["component"] for node in graph["nodes"].values()})
    return [[cid, (Path(directory) / cid / "component.rego").read_text()] for cid in used]


def interfaces_of(components):
    """Each component's interface, evaluated with no input, as set_policy_graph does. A module
    must define exactly the package ``pf.components.<id>``."""
    out = {}
    for cid, source in components:
        if len(source.encode()) > MAX_SOURCE_BYTES:
            raise GraphError(f"component {cid} is larger than {MAX_SOURCE_BYTES} bytes")
        try:
            defined = packages(source)
        except RegoError as e:
            raise GraphError(f"component {cid}: {e}")
        if defined != [component_package(cid)]:
            raise GraphError(f"component {cid} must define package pf.components.{cid}, it defines {defined}")
        out[cid] = eval_rule(source, component_package(cid) + ".interface", {})
    return out


def validate(graph, components):
    """The problems set_policy_graph would refuse the graph for; an empty list means it would
    store it. Returns ``(interfaces, problems)``."""
    ids = [cid for cid, _ in components]
    if len(ids) != len(set(ids)):
        return {}, ["a component is given twice"]
    if len(graph["nodes"]) > MAX_NODES or len(ids) > MAX_COMPONENTS:
        return {}, [f"a graph has at most {MAX_NODES} nodes and {MAX_COMPONENTS} components"]
    try:
        interfaces = interfaces_of(components)
    except GraphError as e:
        return {}, [str(e)]
    problems = eval_rule(VALIDATOR, "data.validate.result", {"graph": graph, "interfaces": interfaces})
    problems += [
        f"component {cid} has more than {MAX_INPUTS} inputs"
        for cid, iface in interfaces.items()
        if len(iface["inputs"]) > MAX_INPUTS
    ]
    if not problems:
        try:
            alternatives(graph, interfaces)
        except GraphError as e:
            problems.append(str(e))
    return interfaces, problems


# ---------------------------------------------------------------- evaluation
def plan(graph, interfaces, presented):
    """The planner's result: ``{order, bindings, missing}``. ``presented`` is the contract's
    view of the presentation, ``{role: [{type, issuer, signer, trusted, subject, claims,
    index, proof_value}]}``."""
    return eval_rule(PLANNER, "data.plan.result", {"graph": graph, "interfaces": interfaces, "presented": presented})


def _supplied_key(spec):
    return "supplied_key" in spec


def _checks_keys(iface):
    """A component with an input it checks against a key it supplies returns key_checks."""
    return any(_supplied_key(spec) for spec in iface["inputs"].values())


def _as_credential(view):
    """A presented credential as a component reads it."""
    return {
        "type": view["type"],
        "issuer": view["issuer"],
        "subject": view["subject"],
        "claims": view["claims"],
        "evidence": [view["index"]],
    }


def _index(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == int(value)


def _well_formed(credential, iface, allowed, key_bound):
    keys = {"type", "subject", "claims", "evidence"}
    if _checks_keys(iface):
        keys.add("key_checks")
    if not (isinstance(credential, dict) and set(credential) == keys):
        return False
    if credential["type"] != iface["output"]:
        return False
    if not (isinstance(credential["subject"], str) and credential["subject"]):
        return False
    if not isinstance(credential["claims"], dict):
        return False
    if not (isinstance(credential["evidence"], list)
            and all(_index(i) and int(i) in allowed for i in credential["evidence"])):
        return False
    if iface["output"] == "Capability":
        if set(credential["claims"]) != {"operation"}:
            return False
        operation = credential["claims"]["operation"]
        if not (isinstance(operation, dict) and set(operation) == {"name", "parameters"}
                and isinstance(operation["name"], str) and operation["name"]
                and isinstance(operation["parameters"], dict)):
            return False
    if "key_checks" in keys:
        for check in credential["key_checks"] if isinstance(credential["key_checks"], list) else [None]:
            if not (isinstance(check, dict) and set(check) == {"index", "key", "key_type"}
                    and _index(check["index"]) and int(check["index"]) in key_bound
                    and isinstance(check["key"], str) and check["key"]
                    and check["key_type"] in KEY_TYPES):
                return False
    return True


def _deny(reason, result, **extra):
    return {"decision": False, "reason": reason, **extra, "order": result["order"], "outputs": result["outputs"]}


def evaluate(graph, components, interfaces, presented, request, policy_data, verifier):
    """issue_policy_credential in graph mode, short of signing: plan, run the active nodes in
    order, decide from the root's capabilities, then verify every presented credential bound
    to an active node.

    ``policy_data`` is ``{node: object}``. ``verifier`` stands in for the contract's
    signature checks: ``verifier.registry(view)`` for a credential checked against the
    registry, ``verifier.key(view, key, key_type)`` for one checked against a key a
    component supplied.

    Returns ``{decision: True, subject, operation, evidence, verified, order, outputs}`` or
    ``{decision: False, reason, [missing], order, outputs}``. A component that returns an
    ill-formed output raises GraphError, as the contract fails the call.
    """
    planned = plan(graph, interfaces, presented)
    result = {"order": planned["order"], "outputs": {}}
    if planned["missing"]:
        return _deny("missing inputs", result, missing=planned["missing"])

    views = {view["index"]: view for creds in presented.values() for view in creds}
    sources = dict(components)
    outputs = result["outputs"]
    for n in planned["order"]:
        node = graph["nodes"][n]
        iface = interfaces[node["component"]]
        inputs, allowed, key_bound = {}, set(), set()
        for name, entries in planned["bindings"][n].items():
            value, every_source_yields = [], True
            for entry in entries:
                if entry["from"] == "presented":
                    creds = [_as_credential(views[i]) for i in entry["indices"]]
                    allowed.update(entry["indices"])
                    if _supplied_key(iface["inputs"][name]):
                        key_bound.update(entry["indices"])
                else:
                    creds = outputs[entry["node"]]
                    for cred in creds:
                        allowed.update(int(i) for i in cred["evidence"])
                every_source_yields = every_source_yields and bool(creds)
                value += creds
            # an input with several sources takes them all, or nothing unless each yields one
            inputs[name] = value if every_source_yields else []
            if len(inputs[name]) > MAX_CREDENTIALS:
                raise GraphError(f"node {n} input {name} takes more than {MAX_CREDENTIALS} credentials")
        if n not in policy_data:
            raise GraphError(f"no policy data object for node {n}")
        out = eval_rule(
            sources[node["component"]],
            component_package(node["component"]) + ".output",
            {"inputs": inputs, "policy_data": policy_data[n], "request": request},
        )
        if not (isinstance(out, list) and len(out) <= MAX_CREDENTIALS
                and all(_well_formed(c, iface, allowed, key_bound) for c in out)):
            raise GraphError(f"node {n} returned an ill-formed output")
        outputs[n] = out

    capabilities = outputs[graph["root"]]
    if not capabilities:
        return _deny("the root issued no capability", result)
    subject, operation = capabilities[0]["subject"], capabilities[0]["claims"]["operation"]
    if any((c["subject"], c["claims"]["operation"]) != (subject, operation) for c in capabilities):
        return _deny("the capabilities disagree", result)

    verified = set()
    for n in planned["order"]:
        iface = interfaces[graph["nodes"][n]["component"]]
        checks = [check for cred in outputs[n] for check in cred["key_checks"]] if _checks_keys(iface) else []
        for name, entries in planned["bindings"][n].items():
            for entry in entries:
                if entry["from"] != "presented":
                    continue
                for i in entry["indices"]:
                    if _supplied_key(iface["inputs"][name]):
                        mine = [c for c in checks if int(c["index"]) == i]
                        ok = bool(mine) and all(verifier.key(views[i], c["key"], c["key_type"]) for c in mine)
                    else:
                        ok = verifier.registry(views[i])
                    if not ok:
                        return _deny("credential verification failed", result)
                    verified.add(i)

    evidence = sorted({int(i) for c in capabilities for i in c["evidence"]})
    return {
        "decision": True,
        "subject": subject,
        "operation": operation,
        "evidence": evidence,
        "verified": sorted(verified),
        "order": result["order"],
        "outputs": outputs,
    }
