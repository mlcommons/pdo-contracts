import json
import os

import pdo.identity.decentralized.identity as identity
import pdo.rego.decentralized.rego_policy_agent as policy_agent
import pdo.identity.decentralized.signature_authority as signature_authority
import pdo.rego.decentralized.rego_token as rego_token
from state import setup_pdo_state, read_var, write_var
from config import SCRATCH_DIR, GUARDIAN_URL
from generate_channel_key import generate_keys, generate_credential
from read_data import read_data
import time

################################################################
issuer_user = "user1"
asset_owner = "user2"
asset_user = "user3"
guardian_url = GUARDIAN_URL
script_dir = os.path.dirname(os.path.abspath(__file__))
# the policy: a graph whose member component checks a "membership" credential against
# its node's policy data, and whose download component issues the capability for the
# key the request names
graph_dir = os.path.join(script_dir, os.path.pardir, "graphs", "download")
graph_path = os.path.join(graph_dir, "graph.json")
components_path = os.path.join(graph_dir, "components")
member_data_path = os.path.join(SCRATCH_DIR, "member_data.json")
# a Hyperledger membership, which the member node allows
membership_credential_path = os.path.join(
    script_dir, os.path.pardir, "credential1.json"
)

public_pem_file, private_pem_file = generate_keys(
    os.path.join(SCRATCH_DIR, "channel_key")
)
public_key_credential_path = generate_credential(public_pem_file, SCRATCH_DIR)
signed_public_key_credential_path = os.path.join(
    SCRATCH_DIR, "credential_key_signed.json"
)
signed_membership_credential_path = os.path.join(
    SCRATCH_DIR, "membership_credential_signed.json"
)

vp_output_file = os.path.join(SCRATCH_DIR, "vp.json")
presentation_file = os.path.join(SCRATCH_DIR, "presentation.json")
policy_credential_path = os.path.join(SCRATCH_DIR, "policy_credential.json")
encrypted_data_path = os.path.join(SCRATCH_DIR, "output_data.bin")
output_data_path = os.path.join(SCRATCH_DIR, "decrypted_output_data.txt")
################################################################


state, _ = setup_pdo_state()


def issuer_setup():
    # setup key authority (issues the public key credential carrying the channel key)
    print("Setting up key signature authority...")
    key_authority = signature_authority.create_signature_authority(
        state, issuer_user, description="key authority"
    )
    write_var(key_authority, "key_authority")
    time.sleep(1)
    print("registering key signing context...")
    signature_authority.register_signing_context(
        state,
        read_var("key_authority"),
        issuer_user,
        path=["key"],
        description="test",
        extensible=False,
    )

    # setup membership authority (issues the institution membership credential)
    print("Setting up membership signature authority...")
    membership_authority = signature_authority.create_signature_authority(
        state, issuer_user, description="membership authority"
    )
    write_var(membership_authority, "membership_authority")
    time.sleep(1)
    print("registering membership signing context...")
    signature_authority.register_signing_context(
        state,
        read_var("membership_authority"),
        issuer_user,
        path=["membership"],
        description="test",
        extensible=False,
    )


def owner_setup():
    # policy setup
    print("Creating rego policy agent...")
    rego_policy = policy_agent.create_rego_policy_agent(
        state, asset_owner, description="test rego policy agent"
    )
    write_var(rego_policy, "rego_policy")

    print("Creating rego token contract...")
    token = rego_token.create_rego_token(state, asset_owner, guardian_url)
    write_var(token, "token")
    time.sleep(1)

    print("Registering token trusted issuer (policy_decision)...")
    rego_token.register_trusted_issuer(
        state,
        read_var("token"),
        read_var("rego_policy"),
        asset_owner,
        credential_types=["policy_decision"],
        path=["__ISSUER__"],
    )

    print("Registering policy agent trusted issuer for public_key...")
    policy_agent.register_trusted_issuer(
        state,
        read_var("rego_policy"),
        read_var("key_authority"),
        asset_owner,
        path=["key"],
        credential_types=["public_key"],
    )

    print("Registering policy agent trusted issuer for membership...")
    policy_agent.register_trusted_issuer(
        state,
        read_var("rego_policy"),
        read_var("membership_authority"),
        asset_owner,
        path=["membership"],
        credential_types=["membership"],
    )
    time.sleep(1)

    print("setting the rego policy, the graph and its components...")
    policy_agent.set_rego_policy(
        state,
        read_var("rego_policy"),
        asset_owner,
        graph=graph_path,
        components=components_path,
    )

    print("setting the member node's policy data...")
    with open(member_data_path, "w") as fp:
        json.dump({"allowedInstitutions": ["Hyperledger"]}, fp)
    policy_agent.set_policy_data(
        state, read_var("rego_policy"), asset_owner, node="member", data=member_data_path
    )


def user_setup():
    # user wallet setup
    print("Creating user wallet...")
    user_wallet = identity.create_identity(state, asset_user, description="user wallet")
    write_var(user_wallet, "user_wallet")


def issued_by(credential_path, authority, out_path):
    """A copy of a credential that names its signer as issuer, which a policy
    agent requires."""
    with open(credential_path) as fp:
        credential = json.load(fp)
    credential["issuer"]["id"] = f"did:pdo:{authority}"
    with open(out_path, "w") as fp:
        json.dump(credential, fp)
    return out_path


# start interactions
def issuer_action():
    print("Issuing public key credential...")
    signature_authority.sign_credential(
        state,
        read_var("key_authority"),
        issuer_user,
        path=["key"],
        credential=issued_by(
            public_key_credential_path,
            read_var("key_authority"),
            os.path.join(SCRATCH_DIR, "public_key_credential.json"),
        ),
        signed_credential=signed_public_key_credential_path,
    )

    print("Issuing membership credential...")
    signature_authority.sign_credential(
        state,
        read_var("membership_authority"),
        issuer_user,
        path=["membership"],
        credential=issued_by(
            membership_credential_path,
            read_var("membership_authority"),
            os.path.join(SCRATCH_DIR, "membership_credential.json"),
        ),
        signed_credential=signed_membership_credential_path,
    )


def user_action():
    print("Adding credentials to user wallet...")
    identity.add_vc(
        state,
        read_var("user_wallet"),
        asset_user,
        credential_file=signed_public_key_credential_path,
    )
    identity.add_vc(
        state,
        read_var("user_wallet"),
        asset_user,
        credential_file=signed_membership_credential_path,
    )

    print("Getting token policy agent...")
    policy_agent_dict = rego_token.list_trusted_issuers(
        state, read_var("token"), asset_user
    )
    retrieved_policy_agent = list(json.loads(policy_agent_dict).keys())[0]
    write_var(retrieved_policy_agent, "retrieved_policy_agent")

    print("Getting requirements for download...")
    requirements = policy_agent.get_requirements(
        state, read_var("retrieved_policy_agent"), asset_user
    )
    # the rego policy agent returns its requirement alternatives, each
    # { role: [credential_type, ...], ... }; present the first one the wallet holds
    held = {"public_key", "membership"}
    alternative = next(
        a for a in requirements if all(t in held for types in a.values() for t in types)
    )
    creds_list = sorted({t for types in alternative.values() for t in types})

    print("generating vp...")
    identity.get_vp(
        state,
        read_var("user_wallet"),
        asset_user,
        save_file="vp.json",
        types=creds_list,
        output_file=vp_output_file,
    )

    # the rego policy agent expects the presentations keyed by role:
    # { "applicant": <verifiable presentation> }
    with open(vp_output_file, "r") as fp:
        vp = json.load(fp)
    with open(presentation_file, "w") as fp:
        json.dump({"applicant": vp}, fp)

    # the graph's download component takes the key the request names
    with open(public_key_credential_path, "r") as fp:
        channel_key = json.load(fp)["credentialSubject"]["claims"]["key"]

    print("Get policy decision vc...")
    policy_agent.issue_policy_credential(
        state,
        read_var("retrieved_policy_agent"),
        asset_user,
        presentation=presentation_file,
        request={"channel_key": channel_key},
        issued_credential=policy_credential_path,
    )

    print("Download data...")
    rego_token.do_operation(
        state,
        read_var("token"),
        asset_user,
        guardian_url,
        vc_file=policy_credential_path,
        output_file=encrypted_data_path,
    )

    print("read downloaded data...")
    read_data(encrypted_data_path, private_pem_file, output_data_path)
    with open(output_data_path, "r") as f:
        print("Downloaded data:")
        print(f.read())


issuer_setup()
owner_setup()
user_setup()
issuer_action()
user_action()
