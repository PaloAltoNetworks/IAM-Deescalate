import os
import sys
import json
import hashlib
import botocore
import logging
import common.shared_tools as st
import common.constants as CONST


def apply_remediation(plan_dir_path, aws_id):
    ''' Go through every plan under the plan_dir_path and apply the remediation policy flaged as patch_me. If is_auto is true, a remediation strategy will be selected automatically  '''
    # Read the remediation plan
    if not os.path.exists(plan_dir_path):
        sys.exit('There is no remediation plan for AWS account {}. Please run the plan command for this account first.'.format(aws_id['account_id']))
    
    aws_session = aws_id['session'] 
    caller_arn = aws_id['arn']

    # Walk through every plan
    for root, dirs, files in os.walk(plan_dir_path, topdown=False):
        for f_name in files:
            f_path = os.path.join(root, f_name)
            patch_principal(st.loadFromJson(f_path), aws_session, caller_arn)

def patch_principal(plan, aws_session, caller_arn):
    ''' Input is a json object of a remediation plan that contains the remediation strategies of a vulnerable principal. The function will find the the strategies marked as "patch_me" and apply it to the aws account as an inline policy. '''    
    if not ('vulnerable_principal' in plan and 'reachable_admin_principals' in plan ):
        return
    src_principal = plan['vulnerable_principal']
    # Skip caller 
    if src_principal == caller_arn:
        return    

    src_principal = st.parse_principal_from_arn(src_principal)

    # Combine all the plan into one policy. This policy needs to be futher optimized to reduce the size!
    policy_dict = dict()
    for dst_principal, edge_list in plan['reachable_admin_principals'].items():
        for edge in edge_list:
            for patch_strategy in edge['remediations']:
                if patch_strategy['patch_me']:
                    # put_inline_policy(src_principal, patch_strategy['policy'], aws_session)
                    _aggregate_policy(patch_strategy['policy'], policy_dict)
    
    if not policy_dict:
        return

    policy_list = list()
    for rsc, action_list in policy_dict.items():
        policy = {'Effect': 'Deny', 'Action': action_list, 'Resource': [rsc]}
        policy_list.append(policy)    
    put_inline_policy(src_principal, policy_list, aws_session)

                    
def _aggregate_policy(policy_list, policy_dict):
    ''' Combine policies. Combine common actions for each resource '''
    for policy in policy_list:
        for rsc in policy['Resource']:
            if not rsc in policy_dict:
                policy_dict[rsc] = list()
            for act in policy['Action']:
                if not act in policy_dict[rsc]: 
                    policy_dict[rsc].append(act)


def put_inline_policy(src_principal, policy, aws_session):
    ''' Apply the de-escalate policy to vulnerable princiapl specified in the plan '''
    inline_policy = dict()
    inline_policy['Version'] = '2012-10-17'
    inline_policy['Statement'] = policy

    client = aws_session.client('iam')
    principal_name = os.path.basename(src_principal)
    rnd_str = _generate_policy_hash(inline_policy)
    policy_name = '{}@{}'.format(CONST.POLICY__PREFIX, rnd_str)
    try:
        if src_principal.startswith('user/'):
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.put_user_policy
            resp = client.put_user_policy(
                PolicyDocument=json.dumps(inline_policy),
                PolicyName=policy_name,
                UserName=principal_name,
            )
        elif src_principal.startswith('role/'):
            resp = client.put_role_policy(
                PolicyDocument=json.dumps(inline_policy),
                PolicyName=policy_name,
                RoleName=principal_name,
            )
        elif src_principal.startswith('group/'):
            resp = client.put_group_policy(
                PolicyDocument=json.dumps(inline_policy),
                PolicyName=policy_name,
                GroupName=principal_name,
            )
    except (botocore.exceptions.ClientError) as error:
        logging.error('Fail to apply inline policy to {}. {}'.format(src_principal, error))
        return
    
    if st.check_boto3_response(resp):
        logging.info('Inline policy has been successfully applied to {}'.format(src_principal))

def _generate_policy_hash(policy_obj):
    ''' generate a hash of the policy object '''

    policy_str = json.dumps(policy_obj, default=str)
    hash_result = hashlib.md5(policy_str.encode())
    return hash_result.hexdigest()
