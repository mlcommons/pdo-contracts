"""A policy graph against a live deployment, decided by its graph tests.

    python startup.py
    python policy_graph_test.py <graph.json> <components folder> <graph_tests.json>
    python cleanup.py

The components folder holds <id>/component.rego; ../graphs/download/ has all three. The tests
name their credentials once and build each test from them (policy_fabric's cards use the same
format):

    {
      "registry":    {<type>: [<signer>, ...]},                 whom the agent trusts, per type
      "request":     {...},                                      what the requester declares
      "policy_data": {<node>: {...}},                            every node's policy data
      "credentials": {<name>: {"type", "issuer", "signer", "subject", "claims"}},
      "tests": [
        {"name": "...",
         "present": {<role>: [<credential name>, ...]},
         "change":  {<credential name>: <JSON merge patch>},       {} for none
         "expect":  {"decision": true, "subject", "operation", "evidence", "verified"}
                 or {"decision": false, "missing": [{"node", "input"} or {"parameter"}]}
                 or {"decision": false, "reason": "<why>"}}
      ]
    }

Every name the tests give an issuer or signer becomes a signature authority, the registry
becomes the agent's trusted issuers, and each test is presented from fresh wallets, one
per role. A credential with a "signing_key" is signed by an authority of its own standing
for that key, under the signer it names, and the key's name stands for that authority's
PEM wherever the tests use it. The names of the issuers and keys are replaced by their
DIDs and PEMs throughout: subjects, claims, policy data, request, expectations and the
graph's trusted_issuers lists. Each node's policy_data in the graph file is replaced by the
tests' policy_data. The contract must reach the decision the test expects: an allow must
issue the expected operation about the expected subject (evidence and verified, which name the
credentials the decision rested on, are not visible on-chain), a denial for a missing input or
parameter must name one of those the test expects missing (the contract's error names the
first it finds), and any other denial's error must contain the expected reason.
"""

import base64
import copy
import json
import os
import sys
import time

import pdo.identity.decentralized.identity as identity
import pdo.identity.decentralized.signature_authority as signature_authority
import pdo.rego.decentralized.rego_policy_agent as policy_agent

from config import SCRATCH_DIR
from state import setup_pdo_state

ISSUER = "user1"
OWNER = "user2"
HOLDER = "user3"

GRAPH_FILE, COMPONENTS, TESTS = (os.path.abspath(arg) for arg in sys.argv[1:4])
with open(GRAPH_FILE) as fp:
    GRAPH = json.load(fp)
with open(TESTS) as fp:
    SUITE = json.load(fp)

state, _ = setup_pdo_state()
os.makedirs(SCRATCH_DIR, exist_ok=True)


def scratch(name):
    return os.path.join(SCRATCH_DIR, name)


def write_json(name, value):
    path = scratch(name)
    with open(path, "w") as fp:
        json.dump(value, fp)
    return path


def read_json(path):
    with open(path) as fp:
        return json.load(fp)


def created(contract_id):
    """A new contract, once its initialization has committed."""
    time.sleep(1)
    return contract_id


def merge_patch(target, patch):
    """RFC 7386, as the tests' changes are written."""
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    out = copy.deepcopy(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            out.pop(key, None)
        else:
            out[key] = merge_patch(out.get(key), value)
    return out


def credentials_of(graph_test):
    """The test's credentials, its changes applied."""
    return {
        name: merge_patch(cred, graph_test["change"][name]) if name in graph_test["change"] else cred
        for name, cred in SUITE["credentials"].items()
    }


# ---------------------------------------------------------------- the issuers
placeholders = sorted(
    {c[key] for graph_test in SUITE["tests"] for c in credentials_of(graph_test).values() for key in ("issuer", "signer")}
    | {d for dids in SUITE["registry"].values() for d in dids}
    | {d for dids in GRAPH["trusted_issuers"].values() for d in dids}
)
authorities = {}
for placeholder in placeholders:
    contract_id = created(signature_authority.create_signature_authority(state, ISSUER, description=placeholder))
    signature_authority.register_signing_context(
        state, contract_id, ISSUER, path=["vc"], description=placeholder, extensible=False
    )
    authorities[placeholder] = contract_id
dids = {placeholder: f"did:pdo:{contract_id}" for placeholder, contract_id in authorities.items()}

key_names = sorted(
    {c["signing_key"] for graph_test in SUITE["tests"] for c in credentials_of(graph_test).values() if "signing_key" in c}
)
key_holders, pems = {}, {}
for key_name in key_names:
    contract_id = created(signature_authority.create_signature_authority(state, ISSUER, description=key_name))
    signature_authority.register_signing_context(
        state, contract_id, ISSUER, path=["vc"], description=key_name, extensible=False
    )
    key_holders[key_name] = contract_id
    pems[key_name] = json.loads(signature_authority.get_verifying_key(
        state, contract_id, ISSUER, path=["vc"], extended=False, filename=None
    ))
real = {**dids, **pems}


def renamed(value):
    """The value with every issuer and key name replaced by its DID or PEM."""
    if isinstance(value, dict):
        return {k: renamed(v) for k, v in value.items()}
    if isinstance(value, list):
        return [renamed(v) for v in value]
    if isinstance(value, str) and value in real:
        return real[value]
    return value


# ---------------------------------------------------------------- the agent
agent = created(policy_agent.create_rego_policy_agent(state, OWNER, description=GRAPH["name"]))
trusted_types = {}
for credential_type, signers in SUITE["registry"].items():
    for signer in signers:
        trusted_types.setdefault(signer, []).append(credential_type)
for signer, types in sorted(trusted_types.items()):
    policy_agent.register_trusted_issuer(
        state, agent, authorities[signer], OWNER, path=["vc"], credential_types=sorted(types)
    )

graph = copy.deepcopy(GRAPH)
graph["trusted_issuers"] = {t: [dids[d] for d in listed] for t, listed in GRAPH["trusted_issuers"].items()}
for node_id, node in graph["nodes"].items():
    node["policy_data"] = renamed(SUITE["policy_data"][node_id])
REQUEST = renamed(SUITE["request"])
policy_agent.set_rego_policy(
    state, agent, OWNER, graph=write_json("policy_graph.json", graph), components=COMPONENTS
)

signed_cache = {}


def signed(name, credential):
    """The credential, naming its issuer and signed by its signer, or with its signing key under
    its signer's name."""
    key = json.dumps(credential, sort_keys=True)
    if key not in signed_cache:
        unsigned = write_json(f"{name}.json", {
            "type": [credential["type"]],
            "issuer": {"id": dids[credential["issuer"]]},
            "credentialSubject": {
                "subject": {"id": renamed(credential["subject"])}, "claims": renamed(credential["claims"])
            },
        })
        path = scratch(f"{name}_{len(signed_cache)}_signed.json")
        signer = key_holders[credential["signing_key"]] if "signing_key" in credential else authorities[credential["signer"]]
        signature_authority.sign_credential(
            state, signer, ISSUER, path=["vc"], credential=unsigned, signed_credential=path
        )
        if "signing_key" in credential:
            vc = read_json(path)
            vc["proof"]["verificationMethod"]["id"] = authorities[credential["signer"]]
            write_json(os.path.basename(path), vc)
        signed_cache[key] = path
    return signed_cache[key]


def presentation(graph_test, number):
    """One fresh wallet per role holding exactly the test's credentials, presented."""
    credentials = credentials_of(graph_test)
    presented = {}
    for role, names in sorted(graph_test["present"].items()):
        wallet = created(identity.create_identity(state, HOLDER, description=f"test {number} {role}"))
        for name in names:
            identity.add_vc(state, wallet, HOLDER, credential_file=signed(name, credentials[name]))
        vp_path = scratch(f"test_{number}_{role}_vp.json")
        identity.get_vp(
            state, wallet, HOLDER, types=sorted({credentials[n]["type"] for n in names}), output_file=vp_path
        )
        presented[role] = read_json(vp_path)
    return write_json(f"test_{number}_presentation.json", presented)


def needs(missing):
    """How the contract's error starts for an input or a parameter of the capability with
    nothing to take."""
    if "parameter" in missing:
        return f"capability parameter {missing['parameter']} needs a "
    return f"node {missing['node']} input {missing['input']} needs a "


def decided(graph_test, number):
    """Whether the contract reached the decision the test expects, and what it did."""
    presentation_file = presentation(graph_test, number)
    issued = scratch(f"test_{number}_decision.json")
    try:
        policy_agent.issue_policy_credential(
            state, agent, HOLDER, presentation=presentation_file, request=REQUEST, issued_credential=issued
        )
        error = None
    except Exception as e:
        error = str(e)
    expect = graph_test["expect"]

    if expect["decision"]:
        if error is not None:
            return False, error
        claims = json.loads(base64.b64decode(read_json(issued)["serializedCredential"]))["credentialSubject"]
        got = {"subject": claims["subject"]["id"], "operation": claims["claims"]}
        return got == renamed({"subject": expect["subject"], "operation": expect["operation"]}), got

    if error is None:
        return False, "allowed"
    if "missing" in expect:
        return any(needs(m) in error for m in expect["missing"]), error
    return expect["reason"] in error, error


failed = 0
for number, graph_test in enumerate(SUITE["tests"]):
    ok, detail = decided(graph_test, number)
    failed += not ok
    print(("PASS  " if ok else "FAIL  ") + graph_test["name"] + ("" if ok else f"  [{detail}]"))
print(f"{len(SUITE['tests']) - failed}/{len(SUITE['tests'])} graph tests decided on-chain as expected")
sys.exit(1 if failed else 0)
