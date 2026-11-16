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

#pragma once

#include <string>

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Util.h"

// The contract initialization hook, the trusted-issuer methods, and the
// policy-data methods are all inherited from ww::identity::policy_agent
// (registered directly in the dispatch table); only the Rego-specific methods
// are declared here.

// set_rego_policy: set the Rego policy, once -- a list of
// [ subpolicy_id, source ] pairs. Trusting the agent means trusting this one
// policy, so it never changes. The method derives and stores the per-role
// requirements, the issue_policy_credential() input schema and the type of
// credential issued from the subpolicies.
#define REGO_POLICY_AGENT_SET_POLICY_PARAM_SCHEMA \
    "{" SCHEMA_KW(rego_modules, []) "}"

// issue_policy_credential: supply the presentations to judge under the
// "presentation" keyword as an object keyed by role,
// { role: <verifiable presentation>, ... }, and the values the requester
// declares (for instance a channel key) under "request", handed to every
// subpolicy or component as input.request. The detailed shape (which roles, each
// value a verifiable presentation) is checked against the schema that
// set_rego_policy stored, or against the roles a graph's alternatives read, so
// this top-level schema only requires objects.
#define REGO_POLICY_AGENT_ISSUE_PARAM_SCHEMA            \
    "{"                                                 \
        SCHEMA_KW(presentation, {}) ","                 \
        SCHEMA_KW(request, {})                          \
    "}"

// Schemas for the two rules every subpolicy must expose. The contract validates a
// subpolicy's output against the matching schema before using it.
//   data.subpolicy.requirements -> { role: [credential_type, ...], ... }
// (roles are arbitrary keys, so the schema can only require an object)
#define REGO_SUBPOLICY_REQUIREMENTS_SCHEMA "{}"

// The operation a policy_decision authorizes: an operation name and its
// parameters. The parameters are opaque (their shape is decided by the operation
// itself), so the schema can only require an object. This is the shape of a
// policy_decision credential's claims, parsed by the rego_token to build the
// guardian capability.
//   { "name": <operation name>, "parameters": { ... } }
#define REGO_OPERATION_SCHEMA                   \
    "{"                                         \
        SCHEMA_KW(name, "") ","                 \
        SCHEMA_KWS(parameters, "{}")            \
    "}"

// A subpolicy returns its verification tasks in two separate lists, each with a
// fixed shape, so the contract knows exactly how to verify each one without
// inspecting the task:
//
//   verification_tasks -- [ { "index": <number> }, ... ]
//       Each credential is verified against the trusted issuer registered for
//       its credential type. Use this for credentials signed by one of the
//       contract's registered trusted issuers.
//
//   vc_supplied_verification_tasks -- [ { "index": <number>, "key": <pem>,
//                                        "key_type": "ec"|"rsa" }, ... ]
//       Each credential is verified against the PEM public key supplied in the
//       task rather than against a trusted issuer. The key is one the subpolicy
//       lifted out of another (already verified) credential -- e.g. a wallet's
//       signing key carried by a WalletVerifyingKeyCredential, or an RSA public key
//       a proof-of-possession credential attests to itself. "key_type" selects
//       the algorithm: "ec" (ECDSA over secp384r1/SHA-384, the scheme PDO
//       credentials are signed with) or "rsa" (RSASSA-PKCS1-v1_5 over SHA-256).
//
// A subpolicy that needs no supplied-key verification returns an empty
// vc_supplied_verification_tasks list. Either way, a credential whose issuer is
// not its signer fails verification.
#define REGO_VERIFICATION_TASK_SCHEMA           \
    "{" SCHEMA_KW(index, 0) "}"

#define REGO_VC_SUPPLIED_VERIFICATION_TASK_SCHEMA       \
    "{"                                                 \
        SCHEMA_KW(index, 0) ","                         \
        SCHEMA_KW(key, "") ","                          \
        SCHEMA_KW(key_type, "")                         \
    "}"

//   data.subpolicy.result ->
//     { decision, verification_tasks, vc_supplied_verification_tasks, credential? }
#define REGO_SUBPOLICY_RESULT_SCHEMA                                    \
    "{"                                                                 \
        SCHEMA_KW(decision, true) ","                                   \
        SCHEMA_KWS(verification_tasks, "[" REGO_VERIFICATION_TASK_SCHEMA "]") "," \
        SCHEMA_KWS(vc_supplied_verification_tasks,                      \
                   "[" REGO_VC_SUPPLIED_VERIFICATION_TASK_SCHEMA "]")   \
    "}"

// The credential to issue. Exactly one subpolicy describes it -- the delivery
// module of an asset's policy, or the rule of an authority -- and it is the one
// that declares the type issued, as data.subpolicy.issues.
//   credential -> { "subject": <DID>, "claims": { ... } }
#define REGO_CREDENTIAL_SCHEMA                  \
    "{"                                         \
        SCHEMA_KW(subject, "") ","              \
        SCHEMA_KW(claims, {})                   \
    "}"

// The top level of a policy graph; the graph validator combinator checks the rest.
//   { "version": 2, "name", "root", "nodes": { <node>: { component, inputs, policy_data } },
//     "trusted_issuers": { <credential type>: [ <DID>, ... ] } }
#define REGO_POLICY_GRAPH_SCHEMA                \
    "{"                                         \
        SCHEMA_KW(version, 0) ","               \
        SCHEMA_KW(name, "") ","                 \
        SCHEMA_KW(root, "") ","                 \
        SCHEMA_KW(nodes, {}) ","                \
        SCHEMA_KW(trusted_issuers, {})          \
    "}"

// set_policy_graph: set the policy as a graph of components, once, instead of
// set_rego_policy (see rego/policy_graph.h and docs/policy_graph.md).
//   { "policy_graph": <graph>, "components": [ [ component_id, source ], ... ] }
#define REGO_POLICY_AGENT_SET_GRAPH_PARAM_SCHEMA                        \
    "{"                                                                 \
        SCHEMA_KWS(policy_graph, REGO_POLICY_GRAPH_SCHEMA) ","          \
        SCHEMA_KWS(components, "[[\"\"]]")                              \
    "}"

// set_node_policy_data: replace one node's policy data
#define REGO_POLICY_AGENT_SET_NODE_DATA_PARAM_SCHEMA    \
    "{"                                                 \
        SCHEMA_KW(node, "") ","                         \
        SCHEMA_KW(policy_data, {})                      \
    "}"

namespace ww
{
namespace rego
{
namespace rego_policy_agent
{
    // set the Rego policy, once (a list of [ subpolicy_id, source ] pairs)
    bool set_rego_policy(const Message& msg, const Environment& env, Response& rsp);

    // return the credential type, the whole list of [ subpolicy_id, source ]
    // pairs, and the merged requirements
    bool get_rego_policy(const Message& msg, const Environment& env, Response& rsp);

    // return the merged per-role credential requirements set by set_rego_policy,
    // or a graph's first requirement alternative
    bool get_requirements(const Message& msg, const Environment& env, Response& rsp);

    // run every subpolicy, merge the results, verify the flagged credentials, and --
    // if the policy allows -- issue a signed credential of the policy's type, as
    // the one subpolicy that describes it says
    bool issue_policy_credential(const Message& msg, const Environment& env, Response& rsp);

    // set the policy as a graph of components, once
    bool set_policy_graph(const Message& msg, const Environment& env, Response& rsp);

    // return the graph, its components and the hash of both
    bool get_policy_graph(const Message& msg, const Environment& env, Response& rsp);

    // return every bundle of presented credentials that can satisfy the policy, by
    // role, smallest first, and the default (the first)
    bool get_requirement_alternatives(const Message& msg, const Environment& env, Response& rsp);

    // replace one node's policy data
    bool set_node_policy_data(const Message& msg, const Environment& env, Response& rsp);

    // plan and run a graph policy over a presentation and return the plan, each
    // node's output and the verdict; nothing is verified or signed
    bool explain_policy_decision(const Message& msg, const Environment& env, Response& rsp);

}; // rego_policy_agent
}; // rego
}; // ww
