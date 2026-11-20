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

import json
import logging
import os

from pdo.contract import invocation_request

import pdo.client.builder as pbuilder
import pdo.client.builder.command as pcommand
import pdo.client.builder.contract as pcontract
import pdo.client.builder.shell as pshell
import pdo.client.commands.contract as pcontract_cmd

import pdo.identity.plugins.policy_agent as policy_agent_plugin

__all__ = [
    "op_initialize",
    "op_set_rego_policy",
    "op_get_rego_policy",
    "op_get_requirements",
    "op_register_trusted_issuer",
    "op_unregister_trusted_issuer",
    "op_list_trusted_issuers",
    "op_set_policy_data",
    "op_get_policy_data",
    "op_issue_policy_credential",
    "cmd_create_rego_policy_agent",
    "cmd_set_rego_policy",
    "cmd_get_rego_policy",
    "cmd_get_requirements",
    "cmd_register_trusted_issuer",
    "cmd_unregister_trusted_issuer",
    "cmd_list_trusted_issuers",
    "cmd_set_policy_data",
    "cmd_get_policy_data",
    "cmd_issue_policy_credential",
    "do_rego_policy_agent",
    "do_rego_policy_agent_contract",
    "load_commands",
]

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# Inherited from the policy_agent plugin -- the initialize, trusted-issuer,
# get_policy_data and get_requirements operations send the same method names and
# parameters here. initialize just marks the contract ready; the policy is set
# separately by set_rego_policy.
# -----------------------------------------------------------------
op_initialize = policy_agent_plugin.op_initialize
op_register_trusted_issuer = policy_agent_plugin.op_register_trusted_issuer
op_unregister_trusted_issuer = policy_agent_plugin.op_unregister_trusted_issuer
op_list_trusted_issuers = policy_agent_plugin.op_list_trusted_issuers
op_get_policy_data = policy_agent_plugin.op_get_policy_data
op_get_requirements = policy_agent_plugin.op_get_requirements

cmd_register_trusted_issuer = policy_agent_plugin.cmd_register_trusted_issuer
cmd_unregister_trusted_issuer = policy_agent_plugin.cmd_unregister_trusted_issuer
cmd_list_trusted_issuers = policy_agent_plugin.cmd_list_trusted_issuers
cmd_get_policy_data = policy_agent_plugin.cmd_get_policy_data
cmd_get_requirements = policy_agent_plugin.cmd_get_requirements
cmd_create_rego_policy_agent = policy_agent_plugin.cmd_create_policy_agent


# -----------------------------------------------------------------
# op_issue_policy_credential
#   Judge the role-keyed presentations, with the values the requester declares,
#   and sign the policy's decision.
# -----------------------------------------------------------------
class op_issue_policy_credential(pcontract.contract_op_base):
    name = "issue_policy_credential"
    help = "judge the presentations and sign the policy's decision"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument(
            "-p",
            "--presentation",
            help="role-keyed verifiable presentations (JSON)",
            type=pbuilder.invocation_parameter,
            required=True,
        )
        subparser.add_argument(
            "-r",
            "--request",
            help="values the requester declares, e.g. the channel key (JSON)",
            type=pbuilder.invocation_parameter,
            required=True,
        )

    @classmethod
    def invoke(cls, state, session_params, presentation, request, **kwargs):
        session_params["commit"] = True
        message = invocation_request(
            "issue_policy_credential", presentation=presentation, request=request
        )
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)
        return result


# -----------------------------------------------------------------
# op_set_rego_policy
#   Set the policy, a graph of components, once.
# -----------------------------------------------------------------
class op_set_rego_policy(pcontract.contract_op_base):
    name = "set_rego_policy"
    help = "set the policy, a graph of components, once"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument(
            "--policy-graph",
            help="the policy graph (JSON)",
            type=pbuilder.invocation_parameter,
            required=True,
        )
        subparser.add_argument(
            "--components",
            help="list of [component_id, source] pairs, as JSON",
            type=pbuilder.invocation_parameter,
            required=True,
        )

    @classmethod
    def invoke(cls, state, session_params, policy_graph, components, **kwargs):
        session_params["commit"] = True
        message = invocation_request("set_rego_policy", policy_graph=policy_graph, components=components)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)
        return result


# -----------------------------------------------------------------
# op_get_rego_policy
#   Fetch the policy graph, its components and the hash of both.
# -----------------------------------------------------------------
class op_get_rego_policy(pcontract.contract_op_base):
    name = "get_rego_policy"
    help = "fetch the policy graph, its components and their hash"

    @classmethod
    def add_arguments(cls, subparser):
        pass

    @classmethod
    def invoke(cls, state, session_params, **kwargs):
        session_params["commit"] = False
        message = invocation_request("get_rego_policy")
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)
        return result


# -----------------------------------------------------------------
# op_set_policy_data
#   Replace one node's policy data.
# -----------------------------------------------------------------
class op_set_policy_data(pcontract.contract_op_base):
    name = "set_policy_data"
    help = "replace the policy data of one node of the policy"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument("--node", help="the node id", type=str, required=True)
        subparser.add_argument(
            "--policy-data",
            help="the node's policy data (JSON)",
            type=pbuilder.invocation_parameter,
            required=True,
        )

    @classmethod
    def invoke(cls, state, session_params, node, policy_data, **kwargs):
        session_params["commit"] = True
        message = invocation_request("set_policy_data", node=node, policy_data=policy_data)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)
        return result


# -----------------------------------------------------------------
# cmd_issue_policy_credential
#   The inherited policy_agent command, with the values the requester declares.
# -----------------------------------------------------------------
class cmd_issue_policy_credential(pcommand.contract_command_base):
    name = "issue_credential"
    help = "Issue a credential based on the current policy"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument(
            "--presentation",
            help="The name of the file where the role-keyed verifiable presentations are stored",
            type=str,
            required=True,
        )
        subparser.add_argument(
            "--request",
            help="values the requester declares, e.g. the channel key (JSON)",
            type=pbuilder.invocation_parameter,
            required=True,
        )
        subparser.add_argument(
            "--issued-credential",
            help="The name of the file where the issued credential will be stored",
            type=str,
            required=True,
        )

    @classmethod
    def invoke(cls, state, context, presentation, request, issued_credential, **kwargs):
        save_file = pcontract_cmd.get_contract_from_context(state, context)
        if not save_file:
            raise ValueError(
                "rego policy agent contract must be created and initialized"
            )

        with open(presentation, "r") as fp:
            presentation_data = json.load(fp)

        session = pbuilder.SessionParameters(save_file=save_file)
        issued_credential_data = pcontract.invoke_contract_op(
            op_issue_policy_credential,
            state,
            context,
            session,
            presentation=presentation_data,
            request=request,
            **kwargs,
        )

        with open(issued_credential, "w") as fp:
            fp.write(issued_credential_data)

        cls.display("saved issued credential to {}".format(issued_credential))
        return True


def _agent_session(state, context):
    save_file = pcontract_cmd.get_contract_from_context(state, context)
    if not save_file:
        raise ValueError("rego policy agent contract must be created and initialized")
    return pbuilder.SessionParameters(save_file=save_file)


# -----------------------------------------------------------------
# cmd_set_rego_policy
#   Reads a graph and, from a folder of <component_id>/component.rego, the components
#   its nodes use.
# -----------------------------------------------------------------
class cmd_set_rego_policy(pcommand.contract_command_base):
    name = "set_rego_policy"
    help = "set the policy, a graph of components, once"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument("--graph", help="the policy graph file (JSON)", type=str, required=True)
        subparser.add_argument(
            "--components",
            help="folder of <component_id>/component.rego",
            type=str,
            required=True,
        )

    @classmethod
    def invoke(cls, state, context, graph, components, **kwargs):
        with open(graph, "r") as fp:
            policy_graph = json.load(fp)
        used = sorted({node["component"] for node in policy_graph["nodes"].values()})
        sources = []
        for component_id in used:
            with open(os.path.join(components, component_id, "component.rego"), "r") as fp:
                sources.append([component_id, fp.read()])

        result = pcontract.invoke_contract_op(
            op_set_rego_policy,
            state,
            context,
            _agent_session(state, context),
            policy_graph=policy_graph,
            components=sources,
            **kwargs,
        )
        cls.display(result)
        return result


# -----------------------------------------------------------------
# cmd_get_rego_policy
# -----------------------------------------------------------------
class cmd_get_rego_policy(pcommand.contract_command_base):
    name = "get_rego_policy"
    help = "fetch the policy graph, its components and their hash"

    @classmethod
    def add_arguments(cls, subparser):
        pass

    @classmethod
    def invoke(cls, state, context, **kwargs):
        result = pcontract.invoke_contract_op(
            op_get_rego_policy, state, context, _agent_session(state, context), **kwargs
        )
        cls.display(result)
        return result


# -----------------------------------------------------------------
# cmd_set_policy_data
# -----------------------------------------------------------------
class cmd_set_policy_data(pcommand.contract_command_base):
    name = "set_policy_data"
    help = "replace the policy data of one node of the policy"

    @classmethod
    def add_arguments(cls, subparser):
        subparser.add_argument("--node", help="the node id", type=str, required=True)
        subparser.add_argument(
            "--data", help="the file holding the node's policy data (JSON)", type=str, required=True
        )

    @classmethod
    def invoke(cls, state, context, node, data, **kwargs):
        with open(data, "r") as fp:
            policy_data = json.load(fp)
        pcontract.invoke_contract_op(
            op_set_policy_data,
            state,
            context,
            _agent_session(state, context),
            node=node,
            policy_data=policy_data,
            **kwargs,
        )
        cls.display("policy data of {} set".format(node))
        return True


# -----------------------------------------------------------------
# Create the generic, shell independent version of the aggregate command
# -----------------------------------------------------------------
__operations__ = [
    op_initialize,
    op_set_rego_policy,
    op_get_rego_policy,
    op_get_requirements,
    op_register_trusted_issuer,
    op_unregister_trusted_issuer,
    op_list_trusted_issuers,
    op_set_policy_data,
    op_get_policy_data,
    op_issue_policy_credential,
]

do_rego_policy_agent_contract = pcontract.create_shell_command(
    "rego_policy_agent_contract", __operations__
)

__commands__ = [
    cmd_create_rego_policy_agent,
    cmd_set_rego_policy,
    cmd_get_rego_policy,
    cmd_get_requirements,
    cmd_register_trusted_issuer,
    cmd_unregister_trusted_issuer,
    cmd_list_trusted_issuers,
    cmd_set_policy_data,
    cmd_get_policy_data,
    cmd_issue_policy_credential,
]

do_rego_policy_agent = pcommand.create_shell_command("rego_policy_agent", __commands__)


# -----------------------------------------------------------------
# Enable binding of the shell independent version to a pdo-shell command
# -----------------------------------------------------------------
def load_commands(cmdclass):
    pshell.bind_shell_command(cmdclass, "rego_policy_agent", do_rego_policy_agent)
    pshell.bind_shell_command(
        cmdclass, "rego_policy_agent_contract", do_rego_policy_agent_contract
    )
