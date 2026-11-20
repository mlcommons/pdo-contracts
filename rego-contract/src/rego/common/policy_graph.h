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
#include <vector>

#include "Util.h"
#include "Value.h"

// Graph mode of the rego_policy_agent: the policy is a graph of Rego components that
// pass credentials to each other, and its capability names the operation it issues, the
// nodes that must all hold, and the presented credential each parameter of the operation
// is read from (see docs/policy_graph.md). These helpers validate a graph, expand its requirement
// alternatives, plan a request and run the planned components. The methods that store
// and evaluate a graph are in methods/rego_policy_agent.cpp.

// Limits; past any of them the contract refuses the graph or the request
#define REGO_GRAPH_MAX_NODES 32
#define REGO_GRAPH_MAX_COMPONENTS 16
#define REGO_GRAPH_MAX_INPUTS 8
#define REGO_GRAPH_MAX_CREDENTIALS 64
#define REGO_GRAPH_MAX_ALTERNATIVES 64
#define REGO_GRAPH_MAX_SOURCE_BYTES (64 * 1024)

namespace ww
{
namespace rego
{
namespace policy_graph
{
    // Evaluate each component's interface (a component is package pf.components.<id>),
    // check the limits, and run the validator combinator over the graph. On success
    // interfaces is { component_id: interface }.
    bool validate_graph(
        const ww::value::Object& graph,
        const ww::value::Array& components,
        ww::value::Object& interfaces,
        std::string& error_msg);

    // The requirement alternatives, each a minimal set of presented credential types
    // keyed by role, { role: [ type, ... ] }, smallest first.
    bool compute_alternatives(
        const ww::value::Object& graph,
        const ww::value::Object& interfaces,
        ww::value::Array& alternatives,
        std::string& error_msg);

    // Run the planner combinator: { order, bindings, parameters, missing } for the
    // presented credential views, { role: [ view, ... ] }.
    bool plan_graph(
        const ww::value::Object& graph,
        const ww::value::Object& interfaces,
        const ww::value::Object& presented,
        ww::value::Object& plan,
        std::string& error_msg);

    // Run the planned nodes in order, each in its own engine over { inputs, policy_data,
    // request }, and check what each returns. views[i] is the view of the presented
    // credential with index i. On success outputs is { node: [ credential, ... ] }.
    bool run_graph(
        const ww::value::Object& graph,
        const ww::value::Array& components,
        const ww::value::Object& interfaces,
        const ww::value::Object& plan,
        const std::vector<ww::value::Object>& views,
        const ww::value::Object& policy_data,
        const ww::value::Object& request,
        ww::value::Object& outputs,
        std::string& error_msg);

    // The capability's verdict: allowed when every node it requires produced a credential,
    // all of them about one subject, and each of its parameters, as the request names it,
    // is the claim of a credential the plan offers it about that subject; the operation
    // is then { name, parameters }. Otherwise reason says why not.
    bool decide(
        const ww::value::Object& graph,
        const ww::value::Object& plan,
        const ww::value::Object& outputs,
        const std::vector<ww::value::Object>& views,
        const ww::value::Object& request,
        bool& allowed,
        std::string& subject,
        ww::value::Object& operation,
        std::string& reason,
        std::string& error_msg);

    // Whether an interface input is one the component checks against a key it supplies.
    bool checks_supplied_key(const ww::value::Object& input_spec);

}; // policy_graph
}; // rego
}; // ww
