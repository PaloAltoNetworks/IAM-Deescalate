"""
Use PMapper to identify principals vulnerable to privilege escalation attacks. 
"""

import logging
import sys
import contextlib
import io
import os 
import shutil
from os import path
from typing import Optional, List
from argparse import ArgumentParser, Namespace
from common import constants as CONST
from common import shared_tools as st

sys.path.insert(0, path.abspath('../PMapper/'))
from principalmapper.util import botocore_tools, arns
from principalmapper.common import Graph
from principalmapper.graphing import graph_actions, graph_cli
from principalmapper.querying.presets import privesc
from principalmapper.querying import query_interface
from principalmapper.common import Node, Graph


logger = logging.getLogger(__name__)

def provide_graph_arguments(create_parser: ArgumentParser):
    ''' Mostly copy from the graph_cli.py in PMapper'''
    # create_parser.add_argument(
    #     '--ignore-orgs',
    #     action='store_true',
    #     help='If specified, skips the check for stored AWS Organizations data and ignores any potentially applicable SCPs during the graph creation process'
    # )
    # Specify the principals that we want to search for potential privilege escalation paths
    create_parser.add_argument(
        '--principal',
        default='*',
        help='A string matching one or more IAM users or roles in the account, or use * (the default) to include all'
    )

    alt_data_source_group = create_parser.add_mutually_exclusive_group()
    alt_data_source_group.add_argument(
        '--localstack-endpoint',
        help='The HTTP(S) endpoint for a running instance of LocalStack'
    )


def create_graph(parsed_args: Namespace):
    ''' Use PMapper's graph_cli to parse the argument and create a graph '''
    # parsed_args = Namespace(account=None, profile='aws_prof', picked_graph_cmd = 'create', include_services=None, exclude_services=None, 
    # localstack_endpoint=None, ignore_orgs = True, include_regions = 'us-east-1', exclude_regions=None)

    # Manually added nenessary parameters for PMapper
    parsed_args.picked_graph_cmd = 'create'
    parsed_args.account = None  # Force to recreate the graph
    parsed_args.include_services = None
    parsed_args.exclude_services = None
    parsed_args.ignore_orgs = True
    parsed_args.include_regions = 'us-east-1'   # Since IAM is global service, it doesn't matter which region we use
    parsed_args.exclude_regions = None

    with contextlib.redirect_stdout(io.StringIO()):
        # surpress stdout from pmapper
        graph_cli.process_arguments(parsed_args)

def query_privesc(aws_profile:str, account_num: str, principal_param: Optional[str]) -> dict:
    ''' 
    Return a dictionary that contain 1. all the admin nodes, 2. nodes and their edges that lead to admin nodes
    Specify the --principal parameter if you only want to focus on a few principals.
    '''
    if account_num is None and aws_profile is None:
        raise ValueError('One of the parameters `account` or `session` must not be None')
        
    if account_num is None:
        session = botocore_tools.get_session(aws_profile)
    else:
        session = None
    graph = graph_actions.get_existing_graph(session, account_num)
    logger.debug('Querying against graph {}'.format(graph.metadata['account_id']))

    nodes = []
    if principal_param is None or principal_param == '*':
        nodes.extend(graph.nodes)
    else:
        nodes.append(graph.get_node_by_searchable_name(principal_param))
    if nodes:
        return get_privesc_info(graph, nodes)


def get_privesc_info(graph: Graph, nodes: List[Node]) -> dict:
    ''' Return a dictionary that contain 1. all the identified admin nodes, 2. nodes and their edges that lead to admin nodes '''
    result = dict()

    for node in nodes:
        # ignore admin nodes
        if node.is_admin:
            if not 'admins' in result:
                result['admins'] = list()
            result['admins'].append(node.searchable_name())
            continue

        # ignore aws-service role
        if st.parse_principal_from_arn(node.arn).startswith('role/aws-service-role/'):
            continue

        esc_edge_list = check_self_escalate(node, result)
        esc_edge_list.extend(check_lateral_escalate(graph, node))

        if not esc_edge_list:
            continue

        if not 'privesc_principal' in result:
            result['privesc_principal'] = dict()
        result['privesc_principal'][node.arn] = esc_edge_list
            
    return result

def check_lateral_escalate(graph: Graph, node: Node) -> List:
    ''' Return a list of edges that directly link the node to an admin node.
        Return None if no privilege escalation edge is found.
        Each edge is represented as a dictionary of (src, short_reason, reason, dst)
    '''
    priv_edge_list = list()
    path_list = privesc.get_search_list(graph, node)   # return a list of edge lists. Each edge list represents a path to a new unique node.
    priv_edge_set = set()   # use set to eliminate duplication
    for path in path_list:         
        edge = path[0]  # we care only the neighbor edge directly connected to the node
        if edge.destination.is_admin:   # successful reach an admin node
            priv_edge_set.add((edge.source.arn, edge.short_reason, edge.reason, edge.destination.arn))
            # priv_edge_set.add((edge.source.searchable_name(), edge.short_reason, edge.reason, edge.destination.searchable_name()))

    # convert each edge tuple to dict 
    if priv_edge_set:
        for edge in priv_edge_set: 
            priv_edge_list.append({
                'src_principal': edge[0],
                'short_reason': edge[1],
                'reason': edge[2],
                'dst_principal': edge[3]
            })
    return priv_edge_list

def check_self_escalate(node, result):
    '''
    This function will update the node.is_admin property and the result dictionary.

    Check if the node is a real admin. PMapper treats principals with any risky action that can escalate itself to the admin as admins. As a result, a princial may be seen as admin even if it has only 1 risk permission like iam:PutUserPolicy. We want to identify thess types of principals and try to "deescalate" them. It is time-consuming to truly verify that a node is a true admin and can accesss every possible actions. In our new definition, we see a node as an admin only if it can access all risky IAM actions and a randomly selected X actions from all AWS's actions. 
    
    Ref: update_admin_status() in https://github.com/nccgroup/PMapper/blob/master/principalmapper/graphing/gathering.py.
    '''
    esc_path = list()
    # The minimal number of escalation paths that a true admin user or role must have
    # A principal with admin policy may not be a real admin. It may be restricted by other policies or SCPs.
    admin_policy_condition = {'iam:PolicyARN': 'arn:aws:iam::aws:policy/AdministratorAccess'}    
    node_type = arns.get_resource(node.arn).split('/')[0]
    if node_type == 'user':
        action = 'iam:PutUserPolicy'
    else:  
        action = 'iam:PutRolePolicy'
    if query_interface.local_check_authorization_handling_mfa(node, action, node.arn, {})[0]:
        edge = _build_self_esc_edge(node.arn, 'IAM', 'can use {} to escalate itself to admin'.format(action))
        esc_path.append(edge)
    
    if node_type == 'user':
        action = 'iam:AttachUserPolicy'
    else:
        action = 'iam:AttachRolePolicy'
    if query_interface.local_check_authorization_handling_mfa(node, action, node.arn, admin_policy_condition)[0]:
        edge = _build_self_esc_edge(node.arn, 'IAM', 'can use {} to escalate itself to admin'.format(action))
        esc_path.append(edge)
    
    if query_interface.local_check_authorization_handling_mfa(node, 'iam:CreateRole', '*', {})[0]:
        # iam:PutRolePolicy is for inline policy, iam:AttachRolePolicy is for managed policy
        if query_interface.local_check_authorization_handling_mfa(node, 'iam:AttachRolePolicy', '*', admin_policy_condition)[0]:
            edge = _build_self_esc_edge(node.arn, 'IAM', 'can use {} and {} to escalate itself to admin'.format('iam:CreateRole', 'iam:AttachRolePolicy'))
            esc_path.append(edge)
        if query_interface.local_check_authorization_handling_mfa(node, 'iam:PutRolePolicy', '*', admin_policy_condition)[0]:
            edge = _build_self_esc_edge(node.arn, 'IAM', 'can use {} and {} to escalate itself to admin'.format('iam:CreateRole', 'iam:PutRolePolicy'))
            esc_path.append(edge)

    for attached_policy in node.attached_policies:
        if attached_policy.arn != node.arn and ':aws:policy/' not in attached_policy.arn:
            # Check if the principal can create a new policy version for custom-managed policy. Not all principals may have custom policies attached
            if query_interface.local_check_authorization_handling_mfa(node, 'iam:CreatePolicyVersion', attached_policy.arn, {})[0]:
                edge = _build_self_esc_edge(node.arn, 'IAM', 'can use {} to escalate itself to admin'.format('iam:CreatePolicyVersion'))
                esc_path.append(edge)
                break  

    if node_type == 'user':
        # Not every user belongs to a group. No need to update action_cnt
        for group in node.group_memberships:
            if query_interface.local_check_authorization_handling_mfa(node, 'iam:PutGroupPolicy', group.arn, {})[0]:
                edge = _build_self_esc_edge(node.arn, 'IAM', 'can use {} to escalate itself to admin'.format('iam:PutGroupPolicy'))
                esc_path.append(edge)
                break
        for group in node.group_memberships:
            if query_interface.local_check_authorization_handling_mfa(node, 'iam:AttachGroupPolicy', group.arn, admin_policy_condition)[0]:
                edge = _build_self_esc_edge(node.arn, 'IAM', 'can use {} to escalate itself to admin'.format('iam:AttachGroupPolicy'))
                esc_path.append(edge)
                break
        for group in node.group_memberships:
            keep_checking = True
            for attached_policy in group.attached_policies:
                if attached_policy.arn != group.arn and ':aws:policy/' not in attached_policy.arn:
                    if query_interface.local_check_authorization_handling_mfa(node, 'iam:CreatePolicyVersion', attached_policy.arn, {})[0]:
                        edge = _build_self_esc_edge(node.arn, 'IAM', 'can use {} to escalate itself to admin'.format('iam:CreatePolicyVersion'))
                        esc_path.append(edge)
                        keep_checking = False
                        break
            if not keep_checking:   # break out group loop
                break
    return esc_path

def _build_self_esc_edge(principal_arn, short_reason, reason):
    edge = {
        'src_principal': principal_arn,
        'short_reason': short_reason,
        'reason': reason,
        'dst_principal': principal_arn
    }
    return edge

def audit_aws(parsed_args, aws_id):
    ''' Use PMapper to create a graph, identify all the admins, and identify principals vulnerable to privilege escalation.
        Input parse_args use the same syntax as PMapper's argquery. aws_id is a dict containing the callerid information.  '''
    account_id = aws_id['account_id'] 
    aws_profile = aws_id['profile']
   
    create_graph(parsed_args)
    parsed_args.account = aws_id['account_id']  # added account_id here so that query_privesc dosn't need to query again
    result = query_privesc(parsed_args.profile, parsed_args.account, parsed_args.principal)

    dir_path = '{}/{}/audit'.format(CONST.OUTPUT_DIR, account_id)
    # delete the existing audit results
    shutil.rmtree(dir_path, ignore_errors = True)
    if result:
        # Add AWS account info
        result['aws_profile'] = aws_profile
        result['aws_id'] = account_id
        os.makedirs(dir_path, exist_ok=True)
        st.dumpToJson(result,'{}/{}'.format(dir_path, CONST.AUDIT_FILE), indent = 4)
    else:
        logging.info('The audit did not find any admin principals or principals vulnerable to privilege escalation !')
        st.dumpToJson('{}','{}/{}'.format(dir_path, CONST.AUDIT_FILE), indent = 4)  # write an empty file
    
    return result
