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
#include "identity/policy_agent.h" // inherited trusted-issuer / policy-data / verify / issue methods
#include "rego/rego_policy_agent.h"
#include "rego/rego_combinators.h" // hardcoded requirement / result combinator policies
#include "rego/policy_graph.h"     // graph mode: validate, expand, plan and run a policy graph
#include "identity/common/Credential.h"
#include "identity/common/did.h"
#include "identity/crypto/Crypto.h"       // SHA384Hash, used for direct-key EC verification
#include "identity/crypto/PublicKey.h"    // EC public key, for direct-key EC verification
#include "identity/crypto/RSAPublicKey.h" // RSA public key, for direct-key RSA verification
#include "rego/rego_evaluator.h" // reused eval_rego (+ the regorus allocator hooks)

// -----------------------------------------------------------------
// State
//   rego_policy_store : this contract's own state. set_rego_policy fills it, once:
//     "rego_modules"  -- [ [ subpolicy_id, source ], ... ]
//     "roles"         -- [ role, ... ]                  (derived from the subpolicies)
//     "input_schema"  -- { role: <verifiable presentation schema>, ... }
//     "credential_type"   -- the type of credential issued (declared by one subpolicy)
//     "issuing_subpolicy" -- the id of the subpolicy that declares it
//   or set_policy_graph fills it, once, for a policy that is a graph of components:
//     "policy_kind"   -- "graph" (a contract without it holds a flat policy, or none)
//     "policy_graph"  -- the graph, each node's policy_data emptied (the values are
//                        in policy_data, keyed by node)
//     "components"    -- [ [ component_id, source ], ... ]
//     "interfaces"    -- { component_id: interface }
//     "roles"         -- [ role, ... ]                  (read by some alternative)
//     "alternatives"  -- [ { role: [credential_type, ...] }, ... ], smallest first
//     "graph_hash"    -- base64 sha256 of the graph and the components, for audits
//   policy_metadata_store : the SAME store the inherited policy_agent methods
//     use. We read "policy_data" / "trusted_issuers" for the Rego input, and
//     write the merged "requirements" there so get_requirements can return them
//     (for a graph, its first requirement alternative); set_policy_graph also
//     writes "policy_data" there, each node's under its node id.
//
// Every subpolicy, every component and each combinator run in their OWN regorus
// engine (see eval_rego), so the fixed module name and entrypoints never collide.
// -----------------------------------------------------------------
static KeyValueStore rego_policy_store("rego_policy_store");
static KeyValueStore policy_metadata_store("policy_metadata_store");

// The contract creation hook (initialize_contract) is inherited directly from
// policy_agent; see contracts/rego_policy_agent.cpp. It primes the identity
// signing contexts, the issuer path used to sign issued credentials, the
// policy-data store, and the trusted-issuers map.

// -----------------------------------------------------------------
// subpolicy module contract
//   Every subpolicy source MUST declare both rules below in `package subpolicy` (regorus
//   errors on an unknown rule path, so neither may be omitted), and each must
//   evaluate to output matching its schema (REGO_SUBPOLICY_REQUIREMENTS_SCHEMA /
//   REGO_SUBPOLICY_RESULT_SCHEMA) -- the contract validates the output before using it.
//
//   data.subpolicy.requirements -> { role: [credential_type, ...], ... }
//       The roles/credential-types this subpolicy needs. Evaluated by set_rego_policy
//       with NO input, so it must be static (it must produce an object even if
//       it is just {}; an empty requirement set is fine).
//
//   data.subpolicy.result -> { "decision": bool,
//                        "verification_tasks": [ { "index": <number> }, ... ],
//                        "credential": { "subject": ..., "claims": {...} } }
//       Evaluated by issue_policy_credential() with input = { presentations,
//       holders, request, trusted_issuers, policy_data }, where policy_data is
//       the subpolicy's own slice, under its subpolicy_id. `index` refers to a
//       credential in input.presentations; the contract verifies each flagged
//       credential's signature in C++. Only the subpolicy that declares issues
//       returns the credential to issue.
//
//   Exactly one subpolicy also declares the type of credential the policy issues;
//   the others leave the rule out, so the contract reads it with a query:
//
//   data.subpolicy.issues -> <credential_type>
//       Evaluated by set_rego_policy with NO input, so it must be static.
// -----------------------------------------------------------------

// eval_rego is reused from the rego_evaluator contract (see
// identity/rego_evaluator.h); each subpolicy and combinator runs in its own
// fresh regorus engine.

// =================================================================
// set_rego_policy helpers
// =================================================================

// -----------------------------------------------------------------
// Ask every subpolicy for the credentials it requires (its "data.subpolicy.requirements"
// rule), then merge them with the requirements combinator. Returns the merged
// requirements ({ role: [credential_type, ...] }) and the list of roles. Every
// subpolicy must return a requirements object (possibly empty); otherwise it errors.
// -----------------------------------------------------------------
static bool compute_requirements(
    const ww::value::Array &modules,
    ww::value::Object &merged_requirements,
    ww::value::Array &roles,
    std::string &error_msg)
{
    // collect each subpolicy's declared requirements (the rule takes no input)
    ww::value::Array subpolicy_requirements;
    std::set<std::string> subpolicy_ids;
    const size_t count = modules.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Array pair;
        if (!modules.get_value(i, pair))
        {
            error_msg.assign("unexpected error, ill-formed module entry");
            return false;
        }
        const char *subpolicy_id = pair.get_string(0);
        const char *source = pair.get_string(1);
        if (subpolicy_id == nullptr || subpolicy_id[0] == '\0' || source == nullptr)
        {
            error_msg.assign("invalid request, ill-formed module pair");
            return false;
        }

        // a subpolicy_id names the subpolicy's slice of the policy data
        if (!subpolicy_ids.insert(subpolicy_id).second)
        {
            error_msg.assign(std::string("invalid request, duplicate module id ") + subpolicy_id);
            return false;
        }

        std::string output_json;
        if (!ww::rego::rego_evaluator::eval_rego(source, "data.subpolicy.requirements", "{}", output_json, error_msg))
            return false;

        // every subpolicy must return a requirements object (an empty {} is fine)
        ww::value::Object req;
        if (!req.deserialize(output_json.c_str()) || !req.validate_schema(REGO_SUBPOLICY_REQUIREMENTS_SCHEMA))
        {
            error_msg.assign("invalid request, a subpolicy returned ill-formed requirements");
            return false;
        }

        if (!subpolicy_requirements.append_value(req))
        {
            error_msg.assign("unexpected error, failed to collect subpolicy requirements");
            return false;
        }
    }

    // merge them with the requirements combinator
    ww::value::Object combinator_input_obj;
    combinator_input_obj.set_value("subpolicy_requirements", subpolicy_requirements);
    std::string combinator_input;
    if (!combinator_input_obj.serialize(combinator_input))
    {
        error_msg.assign("unexpected error, failed to serialize combinator input");
        return false;
    }

    std::string merged_output;
    if (!ww::rego::rego_evaluator::eval_rego(REGO_REQUIREMENTS_COMBINATOR, "data.combine.result", combinator_input, merged_output, error_msg))
        return false;

    ww::value::Object merged;
    if (!merged.deserialize(merged_output.c_str()))
    {
        error_msg.assign("unexpected error, failed to parse merged requirements");
        return false;
    }
    if (!merged.get_value("requirements", merged_requirements))
    {
        error_msg.assign("unexpected error, requirements combinator returned no requirements");
        return false;
    }
    if (!merged.get_value("roles", roles))
    {
        error_msg.assign("unexpected error, requirements combinator returned no roles");
        return false;
    }
    return true;
}

// -----------------------------------------------------------------
// Build the evaluate() input schema from the required roles:
//   { role: <verifiable presentation schema>, ... }
// evaluate() validates its caller's presentations against this so that every
// required role is present and each value is a verifiable presentation. (We do
// not validate the credentials themselves.)
// -----------------------------------------------------------------
static bool build_input_schema(
    const ww::value::Array &roles,
    ww::value::Object &input_schema,
    std::string &error_msg)
{
    ww::value::Object vp_schema;
    if (!vp_schema.deserialize(VERIFIABLE_PRESENTATION_SCHEMA))
    {
        error_msg.assign("unexpected error, failed to parse verifiable presentation schema");
        return false;
    }

    const size_t count = roles.get_count();
    for (size_t i = 0; i < count; i++)
    {
        const char *role = roles.get_string(i);
        if (role == nullptr)
        {
            error_msg.assign("unexpected error, ill-formed role");
            return false;
        }
        if (!input_schema.set_value(role, vp_schema))
        {
            error_msg.assign("unexpected error, failed to build the input schema");
            return false;
        }
    }
    return true;
}

// -----------------------------------------------------------------
// Find the type of credential the policy issues: exactly one subpolicy declares
// it, as a non-empty string, with its "data.subpolicy.issues" rule. Returns the
// type and the id of the subpolicy that declares it.
// -----------------------------------------------------------------
static bool compute_credential_type(
    const ww::value::Array &modules,
    std::string &credential_type,
    std::string &issuing_subpolicy,
    std::string &error_msg)
{
    const size_t count = modules.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Array pair;
        if (!modules.get_value(i, pair))
        {
            error_msg.assign("unexpected error, ill-formed module entry");
            return false;
        }
        const char *subpolicy_id = pair.get_string(0);
        const char *source = pair.get_string(1);
        if (subpolicy_id == nullptr || source == nullptr)
        {
            error_msg.assign("unexpected error, ill-formed module pair");
            return false;
        }

        bool declared = false;
        std::string output_json;
        if (!ww::rego::rego_evaluator::eval_rego_query(source, "data.subpolicy.issues", declared, output_json, error_msg))
            return false;
        if (!declared)
            continue;

        ww::value::String declared_type;
        if (!declared_type.deserialize(output_json.c_str()) || declared_type.get()[0] == '\0')
        {
            error_msg.assign(std::string("invalid request, module ") + subpolicy_id + " declares an ill-formed credential type");
            return false;
        }
        if (!issuing_subpolicy.empty())
        {
            error_msg.assign("invalid request, more than one module declares the credential type");
            return false;
        }
        credential_type.assign(declared_type.get());
        issuing_subpolicy.assign(subpolicy_id);
    }

    if (issuing_subpolicy.empty())
    {
        error_msg.assign("invalid request, no module declares the credential type");
        return false;
    }
    return true;
}

// =================================================================
// Contract methods
// =================================================================

// -----------------------------------------------------------------
// METHOD: set_rego_policy
//   Set the Rego policy: a list of [ subpolicy_id, source ] pairs. The owner may
//   call this only once: the policy is locked, so trusting the agent means
//   trusting this one policy.
//
//   The method also derives the per-role requirements (by invoking each subpolicy's
//   requirements rule and merging them with the requirements combinator),
//   the matching input schema, and the type of credential issued (from the one
//   subpolicy that declares it), then stores all of it.
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_SET_POLICY_PARAM_SCHEMA
//     { "rego_modules": [ [ subpolicy_id, source ], ... ] }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::set_rego_policy(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_POLICY_AGENT_SET_POLICY_PARAM_SCHEMA),
                   "invalid request, missing 'rego_modules'");

    std::string existing_modules;
    ASSERT_SUCCESS(rsp, !rego_policy_store.get("rego_modules", existing_modules) &&
                            !rego_policy_store.get("policy_kind", existing_modules),
                   "invalid request, the rego policy is already set");

    ww::value::Array modules;
    ASSERT_SUCCESS(rsp, msg.get_value("rego_modules", modules),
                   "invalid request, missing rego_modules");
    ASSERT_SUCCESS(rsp, modules.get_count() > 0,
                   "invalid request, rego_modules must not be empty");

    // derive the merged requirements and the roles from the subpolicies
    ww::value::Object merged_requirements;
    ww::value::Array roles;
    std::string error_msg;
    ASSERT_SUCCESS(rsp, compute_requirements(modules, merged_requirements, roles, error_msg),
                   error_msg.c_str());

    // build the evaluate() input schema from those roles
    ww::value::Object input_schema;
    ASSERT_SUCCESS(rsp, build_input_schema(roles, input_schema, error_msg),
                   error_msg.c_str());

    // find the type of credential issued, and the subpolicy that declares it
    std::string credential_type;
    std::string issuing_subpolicy;
    ASSERT_SUCCESS(rsp, compute_credential_type(modules, credential_type, issuing_subpolicy, error_msg),
                   error_msg.c_str());

    // persist the policy, the roles, the input schema, the credential type, and
    // the merged requirements
    std::string serialized;
    ASSERT_SUCCESS(rsp, modules.serialize(serialized),
                   "unexpected error, failed to serialize rego_modules");
    ASSERT_SUCCESS(rsp, rego_policy_store.set("rego_modules", serialized),
                   "unexpected error, failed to persist rego_modules");

    ASSERT_SUCCESS(rsp, roles.serialize(serialized),
                   "unexpected error, failed to serialize roles");
    ASSERT_SUCCESS(rsp, rego_policy_store.set("roles", serialized),
                   "unexpected error, failed to persist roles");

    ASSERT_SUCCESS(rsp, input_schema.serialize(serialized),
                   "unexpected error, failed to serialize input schema");
    ASSERT_SUCCESS(rsp, rego_policy_store.set("input_schema", serialized),
                   "unexpected error, failed to persist input schema");

    ASSERT_SUCCESS(rsp, rego_policy_store.set("credential_type", credential_type) &&
                            rego_policy_store.set("issuing_subpolicy", issuing_subpolicy),
                   "unexpected error, failed to persist the credential type");

    ASSERT_SUCCESS(rsp, merged_requirements.serialize(serialized),
                   "unexpected error, failed to serialize requirements");
    ASSERT_SUCCESS(rsp, policy_metadata_store.set("merged_requirements", serialized),
                   "unexpected error, failed to persist requirements");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_requirements
//   Return the merged per-role requirements set by set_rego_policy, or a graph's
//   first requirement alternative set by set_policy_graph:
//   { role: [ credential_type, ... ], ... }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::get_requirements(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    std::string serialized_requirements;
    ASSERT_SUCCESS(rsp, policy_metadata_store.get("merged_requirements", serialized_requirements),
                   "invalid request, no rego policy has been set");

    ww::value::Object requirements;
    ASSERT_SUCCESS(rsp, requirements.deserialize(serialized_requirements.c_str()),
                   "unexpected error, failed to deserialize requirements");

    return rsp.value(requirements, false);
}

// -----------------------------------------------------------------
// METHOD: get_rego_policy
//   Return the policy: anyone who trusts the agent can read what it checks.
//     { "credential_type": <type>,
//       "rego_modules": [ [ subpolicy_id, source ], ... ],
//       "requirements": { role: [ credential_type, ... ], ... } }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::get_rego_policy(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    std::string serialized_modules;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("rego_modules", serialized_modules),
                   "invalid request, no rego policy has been set");

    ww::value::Array modules;
    ASSERT_SUCCESS(rsp, modules.deserialize(serialized_modules.c_str()),
                   "unexpected error, failed to deserialize rego modules");

    std::string credential_type;
    std::string serialized_requirements;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("credential_type", credential_type) &&
                            policy_metadata_store.get("merged_requirements", serialized_requirements),
                   "unexpected error, failed to fetch the rego policy");

    ww::value::Object requirements;
    ASSERT_SUCCESS(rsp, requirements.deserialize(serialized_requirements.c_str()),
                   "unexpected error, failed to deserialize the rego policy");

    ww::value::Object policy;
    policy.set_string("credential_type", credential_type.c_str());
    policy.set_value("rego_modules", modules);
    policy.set_value("requirements", requirements);
    return rsp.value(policy, false);
}

// =================================================================
// evaluate() helpers
// =================================================================

// -----------------------------------------------------------------
// Standardize the caller's presentations into the shared subpolicy input:
//   input.presentations = { role: [ { type, issuer, signer, trusted, subject, claims, index, proof_value }, ... ], ... }
//   input.holders       = { role: <DID of the holder of the role's presentation> }
//   input.request       = <the values the requester declared>
//   input.trusted_issuers = { issuer_id: [ { verifying_context, credential_types }, ... ] }
//   input.policy_data   = <opaque policy data>, which run_subpolicies replaces
//                         with each subpolicy's own slice
//
// issuer, signer and subject are DIDs. signer is the identity whose key the
// proof verifies against; trust is looked up by it, and verification refuses a
// credential whose issuer names anyone else. trusted says the issuer is its
// signer and the contract trusts that signer for the credential's type, so a
// subpolicy that flags only trusted credentials is never denied by a copy from
// an authority this contract does not accept.
//
// proof_value is the credential's signature (the proof's base64 proofValue). It
// lets a subpolicy match a credential presented on its own against the same
// credential embedded (as a claim) inside another credential, since the embedded
// copy keeps its proof but hides its claims behind a base64 blob.
//
// Roles are taken from the stored `roles` list (so we never enumerate the
// presentations object). For each role we deserialize its verifiable
// presentation, then each verifiable credential, and project a Rego-friendly
// view that keeps the credential's information in a fixed shape.
//
// The per-credential `index` is global across every role. A verification task
// the merged result returns uses it to point back to the exact credential,
// whose full serialized form is kept at the same index in vc_json_by_index.
// -----------------------------------------------------------------
static bool build_rego_input(
    const ww::value::Object &presentations,
    const ww::value::Array &roles,
    const ww::value::Object &request,
    ww::value::Object &rego_input,
    std::vector<std::string> &vc_json_by_index)
{
    ww::value::Object rego_presentations;
    ww::value::Object holders;

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

        holders.set_string(role, ww::identity::did_of(vp.presentation_.holder_.id_).c_str());

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

        ERROR_IF_NOT(rego_presentations.set_value(role, role_creds),
                     "unexpected error, failed to build presentations view");
    }

    // trusted issuers map, reused as-is from the inherited policy_agent store
    ww::value::Object trusted_issuers;
    ERROR_IF_NOT(ww::identity::policy_agent::get_trusted_issuers_map(trusted_issuers),
                 "unexpected error, failed to fetch trusted issuers map");

    // opaque policy data, handed straight to the Rego
    std::string policy_data_str;
    ERROR_IF_NOT(policy_metadata_store.get("policy_data", policy_data_str),
                 "unexpected error, failed to fetch policy data");
    ww::value::Object policy_data;
    ERROR_IF_NOT(policy_data.deserialize(policy_data_str.c_str()),
                 "unexpected error, failed to deserialize policy data");

    rego_input.set_value("presentations", rego_presentations);
    rego_input.set_value("holders", holders);
    rego_input.set_value("request", request);
    rego_input.set_value("trusted_issuers", trusted_issuers);
    rego_input.set_value("policy_data", policy_data);
    return true;
}

// -----------------------------------------------------------------
// Run every subpolicy over the shared input, each with its own slice of the
// policy data (policy_data[subpolicy_id], which must be an object), and collect
// their result objects. Each result is { decision, verification_tasks,
// vc_supplied_verification_tasks }, and the one that describes the credential,
// which must be the issuing subpolicy, also carries credential. On failure
// error_msg explains why.
// -----------------------------------------------------------------
static bool run_subpolicies(
    const ww::value::Array &modules,
    const ww::value::Object &rego_input,
    const std::string &issuing_subpolicy,
    ww::value::Array &subpolicy_outputs,
    std::string &error_msg)
{
    ww::value::Object policy_data;
    if (!rego_input.get_value("policy_data", policy_data))
    {
        error_msg.assign("unexpected error, ill-formed rego input");
        return false;
    }

    const size_t count = modules.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Array pair;
        if (!modules.get_value(i, pair))
        {
            error_msg.assign("unexpected error, ill-formed module entry");
            return false;
        }
        const char *subpolicy_id = pair.get_string(0);
        const char *source = pair.get_string(1);
        if (subpolicy_id == nullptr || source == nullptr)
        {
            error_msg.assign("unexpected error, ill-formed module pair");
            return false;
        }

        ww::value::Object subpolicy_data;
        if (!policy_data.get_value(subpolicy_id, subpolicy_data))
        {
            error_msg.assign(std::string("invalid request, no policy data object for module ") + subpolicy_id);
            return false;
        }

        ww::value::Object subpolicy_input(rego_input);
        std::string input_json;
        if (!subpolicy_input.set_value("policy_data", subpolicy_data) || !subpolicy_input.serialize(input_json))
        {
            error_msg.assign("unexpected error, failed to serialize rego input");
            return false;
        }

        std::string output_json;
        if (!ww::rego::rego_evaluator::eval_rego(source, "data.subpolicy.result", input_json, output_json, error_msg))
            return false;

        // a subpolicy must return a result of the expected shape, and only the
        // issuing subpolicy may describe a credential, which must be well-formed
        ww::value::Object result;
        if (!result.deserialize(output_json.c_str()) || !result.validate_schema(REGO_SUBPOLICY_RESULT_SCHEMA))
        {
            error_msg.assign("unexpected error, a subpolicy returned an ill-formed result");
            return false;
        }
        const bool describes_credential = json_object_has_value(json_value_get_object(result.get()), "credential");
        if (describes_credential && issuing_subpolicy != subpolicy_id)
        {
            error_msg.assign(std::string("unexpected error, module ") + subpolicy_id + " describes a credential but does not declare its type");
            return false;
        }
        ww::value::Object credential;
        if (describes_credential &&
            !(result.get_value("credential", credential) && credential.validate_schema(REGO_CREDENTIAL_SCHEMA)))
        {
            error_msg.assign("unexpected error, a subpolicy described an ill-formed credential");
            return false;
        }
        if (!subpolicy_outputs.append_value(result))
        {
            error_msg.assign("unexpected error, failed to collect module result");
            return false;
        }
    }
    return true;
}

// -----------------------------------------------------------------
// Merge the per-subpolicy outputs with the results combinator:
//   - decision                        : true only if every subpolicy allowed and
//                                       exactly one described the credential
//   - reason                          : why the policy denied, on a denial
//   - verification_tasks              : every subpolicy's trusted-issuer tasks
//   - vc_supplied_verification_tasks  : every subpolicy's supplied-key tasks
//   - credential                      : the credential the one subpolicy described
// On failure error_msg explains why.
// -----------------------------------------------------------------
static bool combine_results(
    const ww::value::Array &subpolicy_outputs,
    bool &decision,
    std::string &reason,
    ww::value::Array &verification_tasks,
    ww::value::Array &vc_supplied_verification_tasks,
    ww::value::Object &credential,
    std::string &error_msg)
{
    ww::value::Object combinator_input_obj;
    combinator_input_obj.set_value("subpolicy_outputs", subpolicy_outputs);
    std::string combinator_input;
    if (!combinator_input_obj.serialize(combinator_input))
    {
        error_msg.assign("unexpected error, failed to serialize combinator input");
        return false;
    }

    std::string merged_output;
    if (!ww::rego::rego_evaluator::eval_rego(REGO_RESULTS_COMBINATOR, "data.combine.result", combinator_input, merged_output, error_msg))
        return false;

    ww::value::Object merged;
    if (!merged.deserialize(merged_output.c_str()))
    {
        error_msg.assign("unexpected error, failed to parse merged result");
        return false;
    }

    ww::value::Boolean decision_value;
    if (!merged.get_value("decision", decision_value))
    {
        error_msg.assign("unexpected error, results combinator returned no decision");
        return false;
    }
    decision = decision_value.get();

    // a denial carries only its reason; an allow, the tasks and the credential
    if (!decision)
    {
        const char *denial_reason = merged.get_string("reason");
        if (denial_reason == nullptr)
        {
            error_msg.assign("unexpected error, results combinator returned no reason");
            return false;
        }
        reason.assign(denial_reason);
        return true;
    }

    if (!merged.get_value("verification_tasks", verification_tasks) ||
        !merged.get_value("vc_supplied_verification_tasks", vc_supplied_verification_tasks) ||
        !merged.get_value("credential", credential))
    {
        error_msg.assign("unexpected error, ill-formed merged result");
        return false;
    }
    return true;
}

// -----------------------------------------------------------------
// Verify the credential's signature directly against a public key the subpolicy
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
// Verify every trusted-issuer task: each credential is checked against the
// trusted issuer registered for its type (the type comes from the credential
// itself, which is trusted). Returns true only if every task's credential
// verifies, returning false at the first one that does not.
// -----------------------------------------------------------------
static bool perform_trusted_issuer_tasks(
    const ww::value::Array &verification_tasks,
    const std::vector<std::string> &vc_json_by_index)
{
    const size_t count = verification_tasks.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Object task;
        if (!verification_tasks.get_value(i, task))
            return false; // malformed task -- cannot verify, so deny

        ww::value::Object vc_object;
        ww::identity::VerifiableCredential vc;
        if (!load_task_credential(task, vc_json_by_index, vc_object, vc))
            return false;

        if (!ww::identity::policy_agent::verify_credential(vc_object, vc, vc.credential_.type_[0]))
            return false; // fail-safe: stop at the first failed verification
    }

    return true;
}

// -----------------------------------------------------------------
// Verify every supplied-key task: each credential is checked against the PEM
// public key carried in the task (see verify_with_supplied_key), using the task's
// key_type, and its issuer must be its signer, as for a trusted issuer. Returns
// true only if every task's credential verifies, returning false at the first
// one that does not.
// -----------------------------------------------------------------
static bool perform_supplied_key_tasks(
    const ww::value::Array &verification_tasks,
    const std::vector<std::string> &vc_json_by_index)
{
    const size_t count = verification_tasks.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Object task;
        if (!verification_tasks.get_value(i, task))
            return false; // malformed task -- cannot verify, so deny

        ww::value::Object vc_object;
        ww::identity::VerifiableCredential vc;
        if (!load_task_credential(task, vc_json_by_index, vc_object, vc))
            return false;

        const char *key = task.get_string("key");
        const char *key_type = task.get_string("key_type");
        if (key == nullptr || key_type == nullptr)
            return false;

        if (ww::identity::contract_id_of(vc.credential_.issuer_.id_) != vc.proof_.verificationMethod_.id_)
            return false;

        if (!verify_with_supplied_key(vc, key, key_type))
            return false; // fail-safe: stop at the first failed verification
    }

    return true;
}

// -----------------------------------------------------------------
// Build and sign the credential the policy described: of the policy's type,
// about the described subject, with the described claims. It is signed with the
// policy agent's issuer key, exactly as policy_agent issues its own credentials,
// and names the agent's DID as its issuer.
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
// graph mode helpers: the policy set by set_policy_graph
// =================================================================

static bool is_graph_policy()
{
    std::string policy_kind;
    return rego_policy_store.get("policy_kind", policy_kind) && policy_kind == "graph";
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
// Plan a graph request and, unless a presented input has nothing to take, run the
// planned nodes. The presentations may leave out a role only some alternatives read,
// but may not name a role the graph never reads. The views of the presented
// credentials are built as for a flat policy (build_rego_input), which numbers them
// role by role, in order.
// -----------------------------------------------------------------
static bool evaluate_graph_request(
    const Message &msg,
    ww::value::Object &graph,
    ww::value::Object &interfaces,
    ww::value::Object &plan,
    ww::value::Object &outputs,
    std::vector<std::string> &vc_json_by_index,
    std::string &error_msg)
{
    ww::value::Object presentations;
    ww::value::Object request;
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

    ww::value::Object rego_input;
    if (!build_rego_input(presentations, presented_roles, request, rego_input, vc_json_by_index))
    {
        error_msg.assign("invalid request, failed to build the rego input");
        return false;
    }

    ww::value::Object presented;
    ww::value::Object policy_data;
    if (!rego_input.get_value("presentations", presented) || !rego_input.get_value("policy_data", policy_data))
    {
        error_msg.assign("unexpected error, ill-formed rego input");
        return false;
    }
    std::vector<ww::value::Object> views;
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
// Verify every presented credential the plan bound to an active node, whether a
// component cited it or not: against the registry, as for a flat policy, and, when
// the graph lists issuers for its type, it must be from one of them; or, for an input
// its component checks against a key it supplies, against every key the node supplied
// for it, of which there must be at least one. Returns false at the first failure.
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
            const JSON_Array *entries = json_object_get_array(node_bindings, name);

            for (size_t e = 0; e < json_array_get_count(entries); e++)
            {
                const JSON_Array *indices = json_object_get_array(json_array_get_object(entries, e), "indices");
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
                        if (!ww::identity::policy_agent::verify_credential(vc_object, vc, type))
                            return false;
                        const JSON_Array *listed = json_object_get_array(trusted, type);
                        bool listed_issuer = json_array_get_count(listed) == 0;
                        const std::string issuer = ww::identity::did_of(vc.credential_.issuer_.id_);
                        for (size_t l = 0; !listed_issuer && l < json_array_get_count(listed); l++)
                            listed_issuer = issuer == json_array_get_string(listed, l);
                        if (!listed_issuer)
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
    }
    return true;
}

// -----------------------------------------------------------------
// issue_policy_credential for a graph policy: plan, run the active nodes, decide from
// the root's capabilities, verify every bound credential, and issue the policy_decision
// whose claims are the capabilities' operation, about their subject.
// -----------------------------------------------------------------
static bool issue_graph_policy_credential(const Message &msg, const Environment &env, Response &rsp)
{
    std::string error_msg;
    ww::value::Object graph;
    ww::value::Object interfaces;
    ww::value::Object plan;
    ww::value::Object outputs;
    std::vector<std::string> vc_json_by_index;
    ASSERT_SUCCESS(rsp, evaluate_graph_request(msg, graph, interfaces, plan, outputs, vc_json_by_index, error_msg),
                   error_msg.c_str());

    // a presented input with nothing to take denies before any component runs
    ww::value::Array missing;
    plan.get_value("missing", missing);
    if (missing.get_count() > 0)
    {
        ww::value::Object first;
        missing.get_value(0, first);
        const std::string reason = std::string("policy evaluation denied, node ") + first.get_string("node") +
            " input " + first.get_string("input") + " needs a " + first.get_string("type") +
            " presented in role " + first.get_string("role");
        return rsp.error(reason.c_str());
    }

    bool allowed = false;
    std::string subject;
    ww::value::Object operation;
    std::string reason;
    ASSERT_SUCCESS(rsp, ww::rego::policy_graph::decide(graph, outputs, allowed, subject, operation, reason, error_msg),
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
// METHOD: issue_policy_credential
//   Standardize the caller's presentations, run every subpolicy, merge their results
//   with the results combinator, and -- if the policy allows -- verify the
//   credentials the merged result flags and issue the signed credential the one
//   subpolicy described, of the policy's type. A graph policy is evaluated by
//   issue_graph_policy_credential instead (docs/policy_graph.md).
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_ISSUE_PARAM_SCHEMA
//     { "presentation": { role: <verifiable presentation>, ... }, "request": { ... } }
//   The keyword is "presentation" (singular), as in the inherited policy_agent
//   issue op; its value is the role -> verifiable presentation map. For a flat
//   policy it is also validated against the per-role schema stored by
//   set_rego_policy (required roles present, each value a verifiable
//   presentation); a graph policy accepts any roles some alternative reads.
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

    // a policy set by set_policy_graph is evaluated as a graph
    if (is_graph_policy())
        return issue_graph_policy_credential(msg, env, rsp);

    ww::value::Object presentations;
    ASSERT_SUCCESS(rsp, msg.get_value("presentation", presentations),
                   "invalid request, missing presentation");

    ww::value::Object request;
    ASSERT_SUCCESS(rsp, msg.get_value("request", request),
                   "invalid request, missing request");

    // ---------- validate against the stored input schema ----------
    std::string serialized_schema;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("input_schema", serialized_schema),
                   "invalid request, no rego policy has been set");
    ASSERT_SUCCESS(rsp, presentations.validate_schema(serialized_schema.c_str()),
                   "invalid request, presentations do not match the required roles");

    // ---------- load the configured policy ----------
    std::string serialized_roles;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("roles", serialized_roles),
                   "invalid request, no rego policy has been set");
    ww::value::Array roles;
    ASSERT_SUCCESS(rsp, roles.deserialize(serialized_roles.c_str()),
                   "unexpected error, failed to deserialize roles");

    std::string serialized_modules;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("rego_modules", serialized_modules),
                   "invalid request, no rego policy has been set");
    ww::value::Array modules;
    ASSERT_SUCCESS(rsp, modules.deserialize(serialized_modules.c_str()),
                   "unexpected error, failed to deserialize rego modules");

    std::string credential_type;
    std::string issuing_subpolicy;
    ASSERT_SUCCESS(rsp, rego_policy_store.get("credential_type", credential_type) &&
                            rego_policy_store.get("issuing_subpolicy", issuing_subpolicy),
                   "invalid request, no rego policy has been set");

    // ---------- standardize the input ----------
    // vc_json_by_index keeps each credential's full serialized form so a
    // verification task can later refer back to it by its global index.
    ww::value::Object rego_input;
    std::vector<std::string> vc_json_by_index;
    ASSERT_SUCCESS(rsp, build_rego_input(presentations, roles, request, rego_input, vc_json_by_index),
                   "invalid request, failed to build the rego input");

    // ---------- run every subpolicy, then merge their outputs ----------
    std::string error_msg;
    ww::value::Array subpolicy_outputs;
    ASSERT_SUCCESS(rsp, run_subpolicies(modules, rego_input, issuing_subpolicy, subpolicy_outputs, error_msg),
                   error_msg.c_str());

    bool decision = false;
    std::string reason;
    ww::value::Array verification_tasks;
    ww::value::Array vc_supplied_verification_tasks;
    ww::value::Object credential;
    ASSERT_SUCCESS(rsp, combine_results(subpolicy_outputs, decision, reason, verification_tasks,
                                        vc_supplied_verification_tasks, credential, error_msg),
                   error_msg.c_str());

    // if the policy denied, stop here -- there is no point verifying signatures
    ASSERT_SUCCESS(rsp, decision, ("policy evaluation denied, " + reason).c_str());

    // ---------- check the described credential against the policy ----------
    const char *subject = credential.get_string("subject");
    ASSERT_SUCCESS(rsp, subject != nullptr && subject[0] != '\0',
                   "unexpected error, the policy described no subject");

    ww::value::Object claims;
    ASSERT_SUCCESS(rsp, credential.get_value("claims", claims),
                   "unexpected error, the policy described no claims");

    // ---------- verify the credentials the merged result flagged ----------
    // the C++ verifier is trusted; the Rego ran over as-yet-unverified claims, so
    // a single failed signature is fail-safe and denies the request. The two task
    // lists are verified two different ways: verification_tasks against their
    // trusted issuers, vc_supplied_verification_tasks against keys the policy supplied.
    ASSERT_SUCCESS(rsp, perform_trusted_issuer_tasks(verification_tasks, vc_json_by_index),
                   "policy evaluation denied, credential verification failed");
    ASSERT_SUCCESS(rsp, perform_supplied_key_tasks(vc_supplied_verification_tasks, vc_json_by_index),
                   "policy evaluation denied, credential verification failed");

    // ---------- issue the signed credential ----------
    ww::value::Object serialized_vc_out;
    ASSERT_SUCCESS(rsp, build_output_credential(env, credential_type, subject, claims, serialized_vc_out),
                   "unexpected error, failed to build the output credential");

    return rsp.value(serialized_vc_out, false);
}

// =================================================================
// Graph mode methods
// =================================================================

// -----------------------------------------------------------------
// METHOD: set_policy_graph
//   Set the policy as a graph of components, once, in place of set_rego_policy. The
//   components' interfaces are evaluated, the graph is checked against them by the
//   graph validator combinator, and its requirement alternatives are expanded; the
//   default (smallest) alternative becomes the policy's requirements. Each node's
//   policy_data in the graph becomes its policy data, which set_node_policy_data
//   replaces later; the stored graph keeps the composition alone.
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_SET_GRAPH_PARAM_SCHEMA
//     { "policy_graph": <graph>, "components": [ [ component_id, source ], ... ] }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::set_policy_graph(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_POLICY_AGENT_SET_GRAPH_PARAM_SCHEMA),
                   "invalid request, missing 'policy_graph' or 'components'");

    std::string existing;
    ASSERT_SUCCESS(rsp, !rego_policy_store.get("rego_modules", existing) &&
                            !rego_policy_store.get("policy_kind", existing),
                   "invalid request, the rego policy is already set");

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

    ww::value::Object default_requirements;
    ASSERT_SUCCESS(rsp, alternatives.get_value(0, default_requirements),
                   "unexpected error, the graph has no requirement alternative");

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
    ASSERT_SUCCESS(rsp, default_requirements.serialize(serialized) &&
                            policy_metadata_store.set("merged_requirements", serialized),
                   "unexpected error, failed to persist requirements");
    ASSERT_SUCCESS(rsp, policy_data.serialize(serialized) && policy_metadata_store.set("policy_data", serialized),
                   "unexpected error, failed to persist the policy data");
    ASSERT_SUCCESS(rsp, rego_policy_store.set("policy_kind", "graph"),
                   "unexpected error, failed to persist the policy kind");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_policy_graph
//   Return the policy graph: anyone who trusts the agent can read what it checks.
//     { "policy_graph": <graph>, "components": [ [ component_id, source ], ... ],
//       "sha256": <base64 hash of both> }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::get_policy_graph(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SUCCESS(rsp, is_graph_policy(), "invalid request, the policy is not a graph");

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
// METHOD: get_requirement_alternatives
//   Return the bundles of presented credential types that can satisfy the policy, by
//   role, smallest first, and the default bundle get_requirements returns. A flat
//   policy has one.
//     { "default": { role: [ credential_type, ... ] },
//       "alternatives": [ { role: [ credential_type, ... ] }, ... ] }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::get_requirement_alternatives(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);

    std::string serialized;
    ASSERT_SUCCESS(rsp, policy_metadata_store.get("merged_requirements", serialized),
                   "invalid request, no rego policy has been set");
    ww::value::Object requirements;
    ASSERT_SUCCESS(rsp, requirements.deserialize(serialized.c_str()),
                   "unexpected error, failed to deserialize requirements");

    ww::value::Array alternatives;
    if (is_graph_policy())
    {
        ASSERT_SUCCESS(rsp, rego_policy_store.get("alternatives", serialized) &&
                                alternatives.deserialize(serialized.c_str()),
                       "unexpected error, failed to load the alternatives");
    }
    else
    {
        alternatives.append_value(requirements);
    }

    ww::value::Object result;
    result.set_value("default", requirements);
    result.set_value("alternatives", alternatives);
    return rsp.value(result, false);
}

// -----------------------------------------------------------------
// METHOD: set_node_policy_data
//   Replace the policy data of one node of a graph policy.
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_SET_NODE_DATA_PARAM_SCHEMA
//     { "node": <node id>, "policy_data": { ... } }
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::set_node_policy_data(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_POLICY_AGENT_SET_NODE_DATA_PARAM_SCHEMA),
                   "invalid request, missing 'node' or 'policy_data'");
    ASSERT_SUCCESS(rsp, is_graph_policy(), "invalid request, the policy is not a graph");

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

// -----------------------------------------------------------------
// METHOD: explain_policy_decision
//   Plan and run a graph policy over a presentation, as issue_policy_credential
//   would, and return what it found; nothing is verified and nothing is signed.
//     { "plan": { order, bindings, missing }, "outputs": { node: [ credential ] },
//       "decision": <bool>, and on a denial "reason" }
//
// JSON PARAMETERS:
//   REGO_POLICY_AGENT_ISSUE_PARAM_SCHEMA
// -----------------------------------------------------------------
bool ww::rego::rego_policy_agent::explain_policy_decision(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_POLICY_AGENT_ISSUE_PARAM_SCHEMA),
                   "invalid request, missing 'presentation' or 'request'");
    ASSERT_SUCCESS(rsp, is_graph_policy(), "invalid request, the policy is not a graph");

    std::string error_msg;
    ww::value::Object graph;
    ww::value::Object interfaces;
    ww::value::Object plan;
    ww::value::Object outputs;
    std::vector<std::string> vc_json_by_index;
    ASSERT_SUCCESS(rsp, evaluate_graph_request(msg, graph, interfaces, plan, outputs, vc_json_by_index, error_msg),
                   error_msg.c_str());

    ww::value::Object result;
    result.set_value("plan", plan);
    result.set_value("outputs", outputs);

    ww::value::Array missing;
    plan.get_value("missing", missing);
    if (missing.get_count() > 0)
    {
        result.set_boolean("decision", false);
        result.set_string("reason", "missing inputs");
        return rsp.value(result, false);
    }

    bool allowed = false;
    std::string subject;
    ww::value::Object operation;
    std::string reason;
    ASSERT_SUCCESS(rsp, ww::rego::policy_graph::decide(graph, outputs, allowed, subject, operation, reason, error_msg),
                   error_msg.c_str());
    result.set_boolean("decision", allowed);
    if (!allowed)
        result.set_string("reason", reason.c_str());
    return rsp.value(result, false);
}
