import os
import sys 
import botocore
import logging
import common.shared_tools as st
import common.constants as CONST


def revert_remediation(plan_path, aws_id, all_principal = False):
    ''' Remove the previously injected inline policies attached to vulnerable principals '''
    aws_session = aws_id['session']
    if all_principal:
        # Enumerate through all the users and roles in this account
        client = aws_session.client('iam')
        resp = client.list_users(
            MaxItems=1000
        )
        for user in resp['Users']:
            src_principal = st.parse_principal_from_arn(user['Arn'])
            unpatch_principal(src_principal, aws_session)
        
        resp = client.list_roles(
            MaxItems=1000
        )
        for role in resp['Roles']:
            src_principal = st.parse_principal_from_arn(role['Arn'])
            unpatch_principal(src_principal, aws_session)
        return

    if not os.path.exists(plan_path):
        sys.exit('There is no remediation plan for this AWS account {}. You may try again with the --all flag'.format(aws_id['account_id']))
    
    # Walk through every remediation plan
    for root, dirs, files in os.walk(plan_path, topdown=False):
        for f_name in files:
            f_path = os.path.join(root, f_name)
            plan = st.loadFromJson(f_path)
            if 'vulnerable_principal' in plan:
                src_principal = st.parse_principal_from_arn(plan['vulnerable_principal'])
                unpatch_principal(src_principal, aws_session) 

def unpatch_principal(src_principal, aws_session):
    ''' Retrieve all the inline policies of the principal and delete the policies starting with iamdeescalate prefix '''    
    client = aws_session.client('iam')
    principal_name = os.path.basename(src_principal)
    if src_principal.startswith('user/'):
        resp = client.list_user_policies(
            UserName=principal_name,
            MaxItems=1000
        )
    elif src_principal.startswith('role/'):
        resp = client.list_role_policies(
            RoleName=principal_name,
            MaxItems=1000
        )
    elif src_principal.startswith('group/'):
        resp = client.list_group_policies(
            GroupName=principal_name,
            MaxItems=1000
        )
    if not 'PolicyNames' in resp:
        return
    for policy_name in resp['PolicyNames']:
        if policy_name.startswith('{}@'.format(CONST.POLICY__PREFIX)):
            # delete this policy
            delete_policy(src_principal, policy_name, aws_session)

def delete_policy(src_principal, policy_name, aws_session):
    client = aws_session.client('iam')
    principal_name = os.path.basename(src_principal)
    try:
        if src_principal.startswith('user/'):
            resp = client.delete_user_policy(
                UserName=principal_name,
                PolicyName=policy_name
            )
        elif src_principal.startswith('role/'):
            resp = client.delete_role_policy(
                RoleName=principal_name,
                PolicyName=policy_name
            )
        elif src_principal.startswith('group/'):
            resp = client.delete_group_policy(
                GroupName=principal_name,
                PolicyName=policy_name
            )
    except (botocore.exceptions.ClientError) as error:
        logging.error('Fail to delete inline {}\'s inline policy {}. {}'.format(src_principal, policy_name, error))
        return
    if st.check_boto3_response(resp):
        logging.info('Inline policy for {} has been deleted'.format(src_principal))
