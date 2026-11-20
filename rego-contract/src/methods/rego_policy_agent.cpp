/* Copyright 2026 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdint.h>
#include <set>
#include <string>
#include <vector>

#include "Dispatch.h"
#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Types.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "Cryptography.h"

#include "contract/base.h"
#include "identity/policy_agent.h" // inherited trusted-issuer / verify / issue methods
#include "rego/rego_policy_agent.h"
#include "rego/common/policy_graph.h" // validate, expand, plan and run a policy graph
#include "identity/common/Credential.h"
#include "identity/common/did.h"
#include "identity/crypto/Crypto.h"       // SHA384Hash, used for direct-key EC verification
#include "identity/crypto/PublicKey.h"    // EC public key, for direct-key EC verification
#include "identity/crypto/RSAPublicKey.h" // RSA public key, for direct-key RSA verification
#include "rego/rego_evaluator.h" // reused eval_rego (+ the regorus allocator hooks)

// -----------------------------------------------------------------
// State
//   rego_policy_store : this contract's own state. set_rego_policy fills it, once,
//   with the policy, a graph of components:
//     "policy_graph"  -- the graph, each node's policy_data emptied (the values are
//                        in policy_data, keyed by node)
//     "components"    -- [ [ component_id, source ], ... ]
//     "interfaces"    -- { component_id: interface }
//     "roles"         -- [ role, ... ]                  (read by some alternative)
//     "alternatives"  -- [ { role: [credential_type, ...] }, ... ], smallest first
//     "graph_hash"    -- base64 sha256 of the graph and the components, for audits
//   policy_metadata_store : the SAME store the inherited policy_agent methods
//     use. We read "trusted_issuers" from it, and keep "policy_data" there, each
//     node's under its node id, which set_policy_data replaces one node at a time
//     and the inherited get_policy_data returns.
//
// Every component and each combinator run in their OWN regorus engine (see
// eval_rego), so the fixed module names and entrypoints never collide.
// -----------------------------------------------------------------
static KeyValueStore rego_policy_store("rego_policy_store");
static KeyValueStore policy_metadata_store("policy_metadata_store");

// The contract creation hook (initialize_contract) is inherited directly from
// policy_agent; see contracts/rego_policy_agent.cpp. It primes the identity
// signing contexts, the issuer path used to sign issued credentials, the
// policy-data store, and the trusted-issuers map.

// eval_rego is reused from the rego_evaluator contract (see
// rego/rego_evaluator.h); each component and combinator runs in its own fresh
// regorus engine.

// =================================================================
// evaluate() helpers
// =================================================================

// -----------------------------------------------------------------
// View the caller's presentations as the planner and the components read them:
//   presented = { role: [ { type, issuer, signer, trusted, subject, claims, index, proof_value }, ... ], ... }
//
// issuer, signer and subject are DIDs. signer is the identity whose key the
// proof verifies against; trust is looked up by it, and verification refuses a
// credential whose issuer names anyone else. trusted says the issuer is its
// signer and the contract trusts that signer for the credential's type, so the
// planner never gives an input a copy from an authority this contract does not
// accept.
//
// proof_value is the credential's signature (the proof's base64 proofValue). It
// lets a component match a credential presented on its own against the same
// credential embedded (as a claim) inside another credential, since the embedded
// copy keeps its proof but hides its claims behind a base64 blob.
//
// Roles are taken from the list given (so we never enumerate the presentations
// object). For each role we deserialize its verifiable presentation, then each
// verifiable credential, and project a Rego-friendly view that keeps the
// credential's information in a fixed shape.
//
// The per-credential `index` is global across every role. Verification uses it
// to point back to the exact credential, whose full serialized form is kept at
// the same index in vc_json_by_index.
// -----------------------------------------------------------------
static bool view_presentations(
    const ww::value::Object &presentations,
    const ww::value::Array &roles,
    ww::value::Object &presented,
    std::vector<std::string> &vc_json_by_index)
{
    const size_t role_count = roles.get_count();
    for (size_t ri = 0; ri < role_count; ri++)
    {
        const char *role = roles.get_string(ri);
        ERROR_IF_NULL(role, "unexpected error, ill-formed role");

        ww::value::Object vp_object;
        ERROR_IF_NOT(presentations.get_value(role, vp_object),
                     "invalid request, missing presentation for a required role");

        ww::identity::VerifiablePresentation vp;
        ERROR_IF_NOT(vp.deserialize(vp_object),
                     "invalid request, ill-formed verifiable presentation");

        ww::value::Array role_creds;
        for (size_t ci = 0; ci < vp.presentation_.verifiableCredential_.size(); ci++)
        {
            ww::identity::VerifiableCredential &vc = vp.presentation_.verifiableCredential_[ci];

            ERROR_IF_NOT(!vc.credential_.type_.empty(),
                         "invalid request, credential missing type list");
            const std::string credential_type = vc.credential_.type_[0];

            // keep the full VC (with proof) so its signature can be checked later
            ww::value::Value vc_value;
            ERROR_IF_NOT(vc.serialize(vc_value),
                         "unexpected error, failed to serialize credential");
            std::string vc_str;
            ERROR_IF_NOT(vc_value.serialize(vc_str),
                         "unexpected error, failed to serialize credential string");

            const size_t index = vc_json_by_index.size();
            vc_json_by_index.push_back(vc_str);

            const std::string &signer = vc.proof_.verificationMethod_.id_;
            ww::identity::VerifyingContext verifier;
            const bool trusted =
                ww::identity::contract_id_of(vc.credential_.issuer_.id_) == signer &&
                ww::identity::policy_agent::fetch_trusted_issuer(
                    signer, credential_type, vc.proof_.verificationMethod_.context_path_, verifier);

            // standardized, Rego-friendly view that keeps all the VC's information
            ww::value::Object cred;
            cred.set_string("type", credential_type.c_str());
            cred.set_string("issuer", ww::identity::did_of(vc.credential_.issuer_.id_).c_str());
            cred.set_string("signer", ww::identity::did_of(signer).c_str());
            cred.set_boolean("trusted", trusted);
            cred.set_string("subject", ww::identity::did_of(vc.credential_.credentialSubject_.subject_.id_).c_str());
            cred.set_value("claims", vc.credential_.credentialSubject_.claims_);
            cred.set_number("index", (double)index);
            cred.set_string("proof_value", vc.proof_.proofValue_.c_str());

            ERROR_IF_NOT(role_creds.append_value(cred),
                         "unexpected error, failed to build credential view");
        }

        ERROR_IF_NOT(presented.set_value(role, role_creds),
                     "unexpected error, failed to build presentations view");
    }

    return true;
}

// -----------------------------------------------------------------
// Verify the credential's signature directly against a public key a component
// supplied, instead of against a trusted issuer. key_type selects the algorithm:
//   "ec"  -- ECDSA over secp384r1 / SHA-384, the scheme PDO credentials use
//   "rsa" -- RSASSA-PKCS1-v1_5 / SHA-256
// The message is the base64 serialized credential the signature was computed
// over (see VerifiableCredential::build / check).
// -----------------------------------------------------------------
static bool verify_with_supplied_key(
    const ww::identity::VerifiableCredential &vc,
    const std::string &key,
    const std::string &key_type)
{
    const std::string serialized_credential(vc.get_serialized_credential());
    ww::types::ByteArray message(serialized_credential.begin(), serialized_credential.end());

    ww::types::ByteArray signature;
    if (!ww::crypto::b64_decode(vc.proof_.proofValue_, signature))
        return false;

    if (key_type == "rsa")
    {
        pdo_contracts::crypto::signing::RSAPublicKey public_key;
        if (!public_key.Deserialize(key))
            return false;
        return public_key.VerifySignature(message, signature);
    }

    if (key_type == "ec")
    {
        pdo_contracts::crypto::signing::PublicKey public_key;
        if (!public_key.Deserialize(key))
            return false;
        return public_key.VerifySignature(message, signature, pdo_contracts::crypto::SHA384Hash);
    }

    return false; // unknown key type -- cannot verify, so deny
}

// -----------------------------------------------------------------
// Look up and deserialize the credential a task points at (by its global index).
// Returns false if the index is out of range or the credential is ill-formed.
// -----------------------------------------------------------------
static bool load_task_credential(
    const ww::value::Object &task,
    const std::vector<std::string> &vc_json_by_index,
    ww::value::Object &vc_object,
    ww::identity::VerifiableCredential &vc)
{
    const int index = (int)task.get_number("index");
    if (index < 0 || (size_t)index >= vc_json_by_index.size())
        return false;

    if (!vc_object.deserialize(vc_json_by_index[index].c_str()))
        return false;

    if (!vc.deserialize(vc_object) || vc.credential_.type_.empty())
        return false;

    return true;
}

// -----------------------------------------------------------------
// Build and sign a credential of the given type, about subject, with claims: the
// policy_decision the graph's capability describes. It is signed with the policy
// agent's issuer key, exactly as policy_agent issues its own credentials, and
// names the agent's DID as its issuer.
// -----------------------------------------------------------------
static bool build_output_credential(
    const Environment &env,
    const std::string &credential_type,
    const std::string &subject,
    const ww::value::Object &claims,
    ww::value::Object &serialized_vc_out)
{
    ww::identity::Credential credential_out;
    credential_out.type_ = {credential_type};
    credential_out.issuer_.id_ = ww::identity::did_of(env.contract_id_);
    credential_out.credentialSubject_.subject_.id_ = subject;

    std::string claims_str;
    ERROR_IF_NOT(claims.serialize(claims_str),
                 "unexpected error, failed to serialize the claims");
    ERROR_IF_NOT(credential_out.credentialSubject_.claims_.deserialize(claims_str.c_str()),
                 "unexpected error, failed to set the claims");

    // sign the credential with the issuer context primed at initialization
    ww::identity::VerifiableCredential vc_out;
    ERROR_IF_NOT(ww::identity::policy_agent::issue_credential(
                     env.originator_id_, env.contract_id_, credential_out, vc_out),
                 "unexpected error, failed to issue the policy credential");

    ERROR_IF_NOT(vc_out.serialize(serialized_vc_out),
                 "unexpected error, failed to serialize the policy credential");
    return true;
}

// =================================================================
// policy helpers: the graph set by set_rego_policy
// =================================================================

static bool policy_is_set()
{
    std::string serialized;
    return rego_policy_store.get("policy_graph", serialized);
}

// -----------------------------------------------------------------
// Load the stored graph policy: the graph, its components, their interfaces, and the
// roles some alternative presents from.
// -----------------------------------------------------------------
static bool load_graph_policy(
    ww::value::Object &graph,
    ww::value::Array &components,
    ww::value::Object &interfaces,
    ww::value::Array &roles)
{
    std::string serialized;
    ERROR_IF_NOT(rego_policy_store.get("policy_graph", serialized) && graph.deserialize(serialized.c_str()),
                 "unexpected error, failed to load the policy graph");
    ERROR_IF_NOT(rego_policy_store.get("components", serialized) && components.deserialize(serialized.c_str()),
                 "unexpected error, failed to load the components");
    ERROR_IF_NOT(rego_policy_store.get("interfaces", serialized) && interfaces.deserialize(serialized.c_str()),
                 "unexpected error, failed to load the interfaces");
    ERROR_IF_NOT(rego_policy_store.get("roles", serialized) && roles.deserialize(serialized.c_str()),
                 "unexpected error, failed to load the roles");
    return true;
}

// -----------------------------------------------------------------
// Plan a graph request and, unless a presented input or a parameter of the capability
// has nothing to take, run the planned nodes. The presentations may leave out a role
// only some alternatives read, but may not name a role the graph never reads.
// view_presentations numbers the presented credentials role by role, in order, and
// views[i] is the view of the credential with index i.
// -----------------------------------------------------------------
static bool evaluate_graph_request(
    const Message &msg,
    ww::value::Object &graph,
    ww::value::Object &interfaces,
    ww::value::Object &plan,
    ww::value::Object &outputs,
    ww::value::Object &request,
    std::vector<ww::value::Object> &views,
    std::vector<std::string> &vc_json_by_index,
    std::string &error_msg)
{
    ww::value::Object presentations;
    if (!msg.get_value("presentation", presentations) || !msg.get_value("request", request))
    {
        error_msg.assign("invalid request, missing 'presentation' or 'request'");
        return false;
    }

    ww::value::Array components;
    ww::value::Array roles;
    if (!load_graph_policy(graph, components, interfaces, roles))
    {
        error_msg.assign("unexpected error, failed to load the policy graph");
        return false;
    }

    const JSON_Object *presented_by_role = json_value_get_object(presentations.get());
    ww::value::Array presented_roles;
    size_t known = 0;
    for (size_t ri = 0; ri < roles.get_count(); ri++)
    {
        const char *role = roles.get_string(ri);
        if (role == nullptr || !json_object_has_value(presented_by_role, role))
            continue;
        ww::value::Object vp_object;
        if (!presentations.get_value(role, vp_object) || !vp_object.validate_schema(VERIFIABLE_PRESENTATION_SCHEMA))
        {
            error_msg.assign(std::string("invalid request, the presentation for ") + role + " is ill-formed");
            return false;
        }
        presented_roles.append_string(role);
        known++;
    }
    if (known != json_object_get_count(presented_by_role))
    {
        error_msg.assign("invalid request, the presentations name a role the policy does not read");
        return false;
    }

    ww::value::Object presented;
    if (!view_presentations(presentations, presented_roles, presented, vc_json_by_index))
    {
        error_msg.assign("invalid request, failed to build the rego input");
        return false;
    }

    std::string serialized;
    ww::value::Object policy_data;
    if (!policy_metadata_store.get("policy_data", serialized) || !policy_data.deserialize(serialized.c_str()))
    {
        error_msg.assign("unexpected error, failed to load the policy data");
        return false;
    }

    for (size_t ri = 0; ri < presented_roles.get_count(); ri++)
    {
        ww::value::Array creds;
        presented.get_value(presented_roles.get_string(ri), creds);
        for (size_t ci = 0; ci < creds.get_count(); ci++)
        {
            ww::value::Object view;
            creds.get_value(ci, view);
            views.push_back(view);
        }
    }

    if (!ww::rego::policy_graph::plan_graph(graph, interfaces, presented, plan, error_msg))
        return false;

    ww::value::Array missing;
    if (!plan.get_value("missing", missing))
    {
        error_msg.assign("unexpected error, the planner returned no missing inputs");
        return false;
    }
    if (missing.get_count() > 0)
        return true;

    return ww::rego::policy_graph::run_graph(
        graph, components, interfaces, plan, views, policy_data, request, outputs, error_msg);
}

// -----------------------------------------------------------------
// Whether a presented credential verifies against the registry for its type and, when
// the graph lists issuers for the type, is from one of them.
// -----------------------------------------------------------------
static bool verify_registered_credential(
    const JSON_Object *trusted,
    const char *type,
    const ww::value::Object &vc_object,
    ww::identity::VerifiableCredential &vc)
{
    if (!ww::identity::policy_agent::verify_credential(vc_object, vc, type))
        return false;
    const JSON_Array *listed = json_object_get_array(trusted, type);
    bool listed_issuer = json_array_get_count(listed) == 0;
    const std::string issuer = ww::identity::did_of(vc.credential_.issuer_.id_);
    for (size_t l = 0; !listed_issuer && l < json_array_get_count(listed); l++)
        listed_issuer = issuer == json_array_get_string(listed, l);
    return listed_issuer;
}

// -----------------------------------------------------------------
// Verify every presented credential the plan bound to an active node, whether a
// component cited it or not, and every one it offered a parameter of the capability:
// against the registry; or, for an input its component checks against a key it
// supplies, against every key the node supplied for it, of which there must be at
// least one. Returns false at the first failure.
// -----------------------------------------------------------------
static bool verify_bound_credentials(
    const ww::value::Object &graph,
    const ww::value::Object &interfaces,
    const ww::value::Object &plan,
    const ww::value::Object &outputs,
    const std::vector<std::string> &vc_json_by_index)
{
    const JSON_Object *nodes = json_object_get_object(json_value_get_object(graph.get()), "nodes");
    const JSON_Object *trusted = json_object_get_object(json_value_get_object(graph.get()), "trusted_issuers");
    const JSON_Array *order = json_object_get_array(json_value_get_object(plan.get()), "order");
    const JSON_Object *bindings = json_object_get_object(json_value_get_object(plan.get()), "bindings");

    for (size_t o = 0; o < json_array_get_count(order); o++)
    {
        const char *node_id = json_array_get_string(order, o);
        const char *component_id = json_object_get_string(json_object_get_object(nodes, node_id), "component");
        const JSON_Object *specs = json_object_get_object(
            json_object_get_object(json_value_get_object(interfaces.get()), component_id), "inputs");
        const JSON_Array *node_outputs = json_object_get_array(json_value_get_object(outputs.get()), node_id);
        const JSON_Object *node_bindings = json_object_get_object(bindings, node_id);

        for (size_t b = 0; b < json_object_get_count(node_bindings); b++)
        {
            const char *name = json_object_get_name(node_bindings, b);
            const JSON_Object *spec = json_object_get_object(specs, name);
            const char *type = json_object_get_string(spec, "type");
            const bool supplied_key = json_object_get_boolean(spec, "supplied_key") == 1;
            const JSON_Array *indices = json_object_get_array(json_object_get_object(node_bindings, name), "indices");

            for (size_t k = 0; k < json_array_get_count(indices); k++)
            {
                const double index = json_array_get_number(indices, k);
                ww::value::Object task;
                task.set_number("index", index);
                ww::value::Object vc_object;
                ww::identity::VerifiableCredential vc;
                if (!load_task_credential(task, vc_json_by_index, vc_object, vc))
                    return false;

                if (!supplied_key)
                {
                    if (!verify_registered_credential(trusted, type, vc_object, vc))
                        return false;
                    continue;
                }

                if (ww::identity::contract_id_of(vc.credential_.issuer_.id_) != vc.proof_.verificationMethod_.id_)
                    return false;
                size_t checked = 0;
                for (size_t c = 0; c < json_array_get_count(node_outputs); c++)
                {
                    const JSON_Array *checks = json_object_get_array(json_array_get_object(node_outputs, c), "key_checks");
                    for (size_t x = 0; x < json_array_get_count(checks); x++)
                    {
                        const JSON_Object *check = json_array_get_object(checks, x);
                        if (json_object_get_number(check, "index") != index)
                            continue;
                        if (!verify_with_supplied_key(vc, json_object_get_string(check, "key"),
                                                      json_object_get_string(check, "key_type")))
                            return false;
                        checked++;
                    }
                }
                if (checked == 0)
                    return false;
            }
        }
    }

    const JSON_Object *specs =
        json_object_get_object(json_object_get_object(json_value_get_object(graph.get()), "capability"), "parameters");
    const JSON_Object *offered = json_object_get_object(json_value_get_object(plan.get()), "parameters");
    for (size_t p = 0; p < json_object_get_count(offered); p++)
    {
        const char *name = json_object_get_name(offered, p);
        const char *type = json_object_get_string(json_object_get_object(specs, name), "type");
        const JSON_Array *indices = json_object_get_array(offered, name);
        for (size_t k = 0; k < json_array_get_count(indices); k++)
        {
            ww::value::Object task;
            task.set_number("index", json_array_get_number(indices, k));
            ww::value::Object vc_object;
            ww::identity::VerifiableCredential vc;
            if (!load_task_credential(task, vc_json_by_index, vc_object, vc) ||
                !verify_registered_credential(trusted, type, vc_object, vc))
                return false;
        }
    }
    return true;
}

// =================================================================
// Contract methods
// =================================================================

// -----------------------------------------------------------------
// METHOD: issue_policy_credential
//   Plan the request, run the active nodes, decide from what the nodes the capability
//   requires produced, verify every credential the plan bound to an active node or
//   offered a parameter, and issue the policy_decision whose claims are the
//   capability's operation, about its subject (docs/policy_graph.md).
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_ISSUE_PARAM_SCHEMA
//     { "presentation": { role: <verifiable presentation>, ... }, "request": { ... } }
//   The keyword is "presentation" (singular), as in the inherited policy_agent
//   issue op; its value is the role -> verifiable presentation map, which may
//   leave out a role only some requirement alternatives read.
//
// RETURNS:
//   VERIFIABLE_CREDENTIAL_SCHEMA -- the signed credential, or an error saying
//   why the policy denied.
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::issue_policy_credential(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_POLICY_AGENT_ISSUE_PARAM_SCHEMA),
                   "invalid request, missing 'presentation' or 'request'");
    ASSERT_SUCCESS(rsp, policy_is_set(), "invalid request, no rego policy has been set");

    std::string error_msg;
    ww::value::Object graph;
    ww::value::Object interfaces;
    ww::value::Object plan;
    ww::value::Object outputs;
    ww::value::Object request;
    std::vector<ww::value::Object> views;
    std::vector<std::string> vc_json_by_index;
    ASSERT_SUCCESS(rsp, evaluate_graph_request(msg, graph, interfaces, plan, outputs, request, views,
                                               vc_json_by_index, error_msg),
                   error_msg.c_str());

    // a presented input or a parameter with nothing to take denies before any component runs
    ww::value::Array missing;
    plan.get_value("missing", missing);
    if (missing.get_count() > 0)
    {
        ww::value::Object first;
        missing.get_value(0, first);
        const char *parameter = first.get_string("parameter");
        const std::string needs = std::string(" needs a ") + first.get_string("type") + " presented in role " +
            first.get_string("role");
        const std::string reason = parameter != nullptr
            ? std::string("policy evaluation denied, capability parameter ") + parameter + needs
            : std::string("policy evaluation denied, node ") + first.get_string("node") + " input " +
                first.get_string("input") + needs;
        return rsp.error(reason.c_str());
    }

    bool allowed = false;
    std::string subject;
    ww::value::Object operation;
    std::string reason;
    ASSERT_SUCCESS(rsp, ww::rego::policy_graph::decide(graph, plan, outputs, views, request, allowed, subject, operation,
                                                       reason, error_msg),
                   error_msg.c_str());
    ASSERT_SUCCESS(rsp, allowed, ("policy evaluation denied, " + reason).c_str());

    // the planner and the components read unverified claims, so nothing is signed until
    // every credential they were given verifies
    ASSERT_SUCCESS(rsp, verify_bound_credentials(graph, interfaces, plan, outputs, vc_json_by_index),
                   "policy evaluation denied, credential verification failed");

    ww::value::Object serialized_vc_out;
    ASSERT_SUCCESS(rsp, build_output_credential(env, "policy_decision", subject, operation, serialized_vc_out),
                   "unexpected error, failed to build the output credential");

    return rsp.value(serialized_vc_out, false);
}

// -----------------------------------------------------------------
// METHOD: set_rego_policy
//   Set the policy, a graph of components, once: the policy is locked, so trusting
//   the agent means trusting this one policy. The components' interfaces are
//   evaluated, the graph is checked against them by the graph validator combinator,
//   and its requirement alternatives are expanded. Each node's policy_data in the
//   graph becomes its policy data, which set_policy_data replaces later; the stored
//   graph keeps the composition alone.
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_SET_POLICY_PARAM_SCHEMA
//     { "policy_graph": <graph>, "components": [ [ component_id, source ], ... ] }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::set_rego_policy(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_POLICY_AGENT_SET_POLICY_PARAM_SCHEMA),
                   "invalid request, missing 'policy_graph' or 'components'");

    ASSERT_SUCCESS(rsp, !policy_is_set(), "invalid request, the rego policy is already set");

    ww::value::Object graph;
    ww::value::Array components;
    ASSERT_SUCCESS(rsp, msg.get_value("policy_graph", graph) && msg.get_value("components", components),
                   "invalid request, missing 'policy_graph' or 'components'");

    std::string error_msg;
    ww::value::Object interfaces;
    ASSERT_SUCCESS(rsp, ww::rego::policy_graph::validate_graph(graph, components, interfaces, error_msg),
                   error_msg.c_str());

    ww::value::Array alternatives;
    ASSERT_SUCCESS(rsp, ww::rego::policy_graph::compute_alternatives(graph, interfaces, alternatives, error_msg),
                   error_msg.c_str());

    std::set<std::string> role_set;
    for (size_t a = 0; a < alternatives.get_count(); a++)
    {
        ww::value::Object alternative;
        alternatives.get_value(a, alternative);
        const JSON_Object *by_role = json_value_get_object(alternative.get());
        for (size_t r = 0; r < json_object_get_count(by_role); r++)
            role_set.insert(json_object_get_name(by_role, r));
    }
    ww::value::Array roles;
    for (const std::string &role : role_set)
        roles.append_string(role.c_str());

    // split each node's policy data from the composition
    JSON_Value *composition_value = json_value_deep_copy(graph.get());
    JSON_Value *policy_data_value = json_value_init_object();
    JSON_Object *nodes = json_object_get_object(json_value_get_object(composition_value), "nodes");
    for (size_t n = 0; n < json_object_get_count(nodes); n++)
    {
        JSON_Object *node = json_value_get_object(json_object_get_value_at(nodes, n));
        json_object_set_value(json_value_get_object(policy_data_value), json_object_get_name(nodes, n),
                              json_value_deep_copy(json_object_get_value(node, "policy_data")));
        json_object_set_value(node, "policy_data", json_value_init_object());
    }
    ww::value::Object stored_graph;
    ww::value::Object policy_data;
    const bool split = stored_graph.set(composition_value) != nullptr && policy_data.set(policy_data_value) != nullptr;
    json_value_free(composition_value);
    json_value_free(policy_data_value);
    ASSERT_SUCCESS(rsp, split, "unexpected error, failed to split the policy data from the graph");

    // the hash ties a decision to the exact composition that made it
    ww::value::Object composition;
    std::string serialized;
    ASSERT_SUCCESS(rsp, composition.set_value("policy_graph", stored_graph) &&
                            composition.set_value("components", components) && composition.serialize(serialized),
                   "unexpected error, failed to serialize the policy graph");
    ww::types::ByteArray composition_bytes(serialized.begin(), serialized.end());
    ww::types::ByteArray hash;
    std::string graph_hash;
    ASSERT_SUCCESS(rsp, ww::crypto::hash::sha256_hash(composition_bytes, hash) && ww::crypto::b64_encode(hash, graph_hash),
                   "unexpected error, failed to hash the policy graph");

    ASSERT_SUCCESS(rsp, stored_graph.serialize(serialized) && rego_policy_store.set("policy_graph", serialized),
                   "unexpected error, failed to persist the policy graph");
    ASSERT_SUCCESS(rsp, components.serialize(serialized) && rego_policy_store.set("components", serialized),
                   "unexpected error, failed to persist the components");
    ASSERT_SUCCESS(rsp, interfaces.serialize(serialized) && rego_policy_store.set("interfaces", serialized),
                   "unexpected error, failed to persist the interfaces");
    ASSERT_SUCCESS(rsp, roles.serialize(serialized) && rego_policy_store.set("roles", serialized),
                   "unexpected error, failed to persist the roles");
    ASSERT_SUCCESS(rsp, alternatives.serialize(serialized) && rego_policy_store.set("alternatives", serialized),
                   "unexpected error, failed to persist the alternatives");
    ASSERT_SUCCESS(rsp, rego_policy_store.set("graph_hash", graph_hash),
                   "unexpected error, failed to persist the graph hash");
    ASSERT_SUCCESS(rsp, policy_data.serialize(serialized) && policy_metadata_store.set("policy_data", serialized),
                   "unexpected error, failed to persist the policy data");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_rego_policy
//   Return the policy: anyone who trusts the agent can read what it checks.
//     { "policy_graph": <graph>, "components": [ [ component_id, source ], ... ],
//       "sha256": <base64 hash of both> }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::get_rego_policy(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SUCCESS(rsp, policy_is_set(), "invalid request, no rego policy has been set");

    ww::value::Object graph;
    ww::value::Array components;
    ww::value::Object interfaces;
    ww::value::Array roles;
    std::string graph_hash;
    ASSERT_SUCCESS(rsp, load_graph_policy(graph, components, interfaces, roles) &&
                            rego_policy_store.get("graph_hash", graph_hash),
                   "unexpected error, failed to load the policy graph");

    ww::value::Object result;
    result.set_value("policy_graph", graph);
    result.set_value("components", components);
    result.set_string("sha256", graph_hash.c_str());
    return rsp.value(result, false);
}

// -----------------------------------------------------------------
// METHOD: get_requirements
//   Return the bundles of presented credential types that can satisfy the policy, by
//   role, smallest first:
//     [ { role: [ credential_type, ... ] }, ... ]
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::get_requirements(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SUCCESS(rsp, policy_is_set(), "invalid request, no rego policy has been set");

    std::string serialized;
    ww::value::Array alternatives;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("alternatives", serialized) &&
                            alternatives.deserialize(serialized.c_str()),
                   "unexpected error, failed to load the alternatives");
    return rsp.value(alternatives, false);
}

// -----------------------------------------------------------------
// METHOD: set_policy_data
//   Replace the policy data of one node of the policy.
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_SET_POLICY_DATA_PARAM_SCHEMA
//     { "node": <node id>, "policy_data": { ... } }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::set_policy_data(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_POLICY_AGENT_SET_POLICY_DATA_PARAM_SCHEMA),
                   "invalid request, missing 'node' or 'policy_data'");
    ASSERT_SUCCESS(rsp, policy_is_set(), "invalid request, no rego policy has been set");

    const char *node_id = msg.get_string("node");
    ww::value::Object node_data;
    ASSERT_SUCCESS(rsp, node_id != nullptr && msg.get_value("policy_data", node_data),
                   "invalid request, missing 'node' or 'policy_data'");

    ww::value::Object graph;
    ww::value::Array components;
    ww::value::Object interfaces;
    ww::value::Array roles;
    ASSERT_SUCCESS(rsp, load_graph_policy(graph, components, interfaces, roles),
                   "unexpected error, failed to load the policy graph");
    const JSON_Object *nodes = json_object_get_object(json_value_get_object(graph.get()), "nodes");
    ASSERT_SUCCESS(rsp, json_object_has_value(nodes, node_id),
                   (std::string("invalid request, the graph has no node ") + node_id).c_str());

    std::string serialized;
    ww::value::Object policy_data;
    ASSERT_SUCCESS(rsp, policy_metadata_store.get("policy_data", serialized) &&
                            policy_data.deserialize(serialized.c_str()),
                   "unexpected error, failed to load the policy data");
    JSON_Value *updated = json_value_deep_copy(policy_data.get());
    json_object_set_value(json_value_get_object(updated), node_id, json_value_deep_copy(node_data.get()));
    const bool kept = policy_data.set(updated) != nullptr && policy_data.serialize(serialized);
    json_value_free(updated);
    ASSERT_SUCCESS(rsp, kept && policy_metadata_store.set("policy_data", serialized),
                   "unexpected error, failed to persist the policy data");

    return rsp.success(true);
}
