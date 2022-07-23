import os
import sys
import shutil
import logging
import common.shared_tools as st

from remediation import autoscale_handler, cf_handler, codebuild_handler, cross_handler, ec2_handler, iam_handler, lambda_handler, sagemaker_handler, ssm_handler,sts_handler


def plan_remediation(audit_file_path, output_dir_path, aws_id, is_auto = False):
    ''' Read the audit output from audit_file_path. For each possible privilege escalation path, create a remediation plan that contains one or multiple strategy. If is_auto is set to True, the first strategy's "patch_me" field of every plan will be set to 1. '''
    if not os.path.exists(audit_file_path):
        sys.exit('There is no audit result for this AWS account. Please run the audit command on this account first.')
    audit_result = st.loadFromJson(audit_file_path)
    if not 'privesc_principal' in audit_result:
        # https://unicode.org/emoji/charts/full-emoji-list.html
        logging.info('No non-admin principal is vulnerable to privilege escalation in AWS account {} \N{slightly smiling face}'.format(audit_result['aws_id']))
        shutil.rmtree(output_dir_path, ignore_errors = True)
        sys.exit(0)
    plan_dict = dict()
    for principal_arn, esc_edge_list in audit_result['privesc_principal'].items():
        if principal_arn == aws_id['arn']:
            # skip caller 
            continue
        for esc_edge in esc_edge_list:
            src_principal = esc_edge['src_principal'] 
            short_reason = esc_edge['short_reason']
            reason = esc_edge['reason']
            dst_principal = esc_edge['dst_principal'] 

            if not src_principal in plan_dict:
                plan_dict[src_principal] = dict()
            if not dst_principal in plan_dict[src_principal]:
                plan_dict[src_principal][dst_principal] = list()    # a list of possible edges from src_principal to dst_principal

            edge_remediation = {'reason': reason, 'remediations': list()}
            # get a list of strategy that can break this edge. Any strategy in this list can break the edge
            strategy_list = get_remediation_plan(src_principal, dst_principal, short_reason, reason)
            if not strategy_list:
                logging.warn('No remediation plan for: {} {} {}'.format(src_principal, reason, dst_principal))
                continue
            idx = 0
            for strategy in strategy_list:
                # Pick the first strategy and mark patch_me to 1
                patch_me = 1 if (idx == 0 and is_auto) else 0    
                edge_remediation['remediations'].append({'policy': strategy.process_list, 'patch_me':patch_me})
                idx += 1

            plan_dict[src_principal][dst_principal].append(edge_remediation)

    output_remediation_plan(plan_dict, output_dir_path)

def get_remediation_plan(src_principal, dst_principal, short_reason, reason):
    ''' The four input parameters represent an edge, a lateral movement from one principal to another. 
        The function return a list of strategies. Any strategy in the list can break the edge (de-escalate).  
        :param src_principal: a user or role that can be escalated
        :param dst_principal: the escalated user or role that src_principal can eventually achieve
        :param short_reason: the short_reason output from PMapper
        :param reason: the reason output from PMapper
        :return a list of RemediationStrategy 
        :rtype list[RemediationStrategy] '''
        
    if short_reason == 'EC2 Auto Scaling':
        handler = autoscale_handler.AutoscalHandler()
    elif short_reason == 'Cloudformation':
        handler = cf_handler.CFHandler()
    elif short_reason == 'CodeBuild':
        handler = codebuild_handler.CodebuildHandler()
    elif short_reason == 'STS':
        handler = cross_handler.CrossHandler()
    elif short_reason == 'EC2':
        handler = ec2_handler.EC2Handler()
    elif short_reason == 'IAM':
        handler = iam_handler.IAMHandler()
    elif short_reason == 'Lambda':
        handler = lambda_handler.LambdaHandler()
    elif short_reason == 'SageMaker':
        handler = sagemaker_handler.SagemakerHandler()
    elif short_reason == 'SSM':
        handler = ssm_handler.SSMHandler()
    elif short_reason == 'AssumeRole':
        handler = sts_handler.STSHandler()
    else:
        logging.error('Unrecognized PMapper short reason {}'.format(short_reason))
        return
    return handler.get_remediation_plan(src_principal, dst_principal, reason)

def output_remediation_plan(plan_dict, output_dir_path):
    ''' Create one file for each vulnerable principal. The file contains the destinations that this principal can escalate to, and the policies to remediate the issues. There may be multiple edges between each src_principal and dst_principal. In each edge, there are multiple ways that this edge can be broken.
    Users just need to set one of the "patch_me" to 1 under each remediations block. '''
    # create a directory for this AWS account's plan
    shutil.rmtree(output_dir_path, ignore_errors = True)
    os.makedirs(output_dir_path, exist_ok=True)
    
    # create one file for each principal suspectable to privesc attack
    for src_principal, dst_list in plan_dict.items():
        # Parse the path of src_principal
        principal = st.parse_principal_from_arn(src_principal)
        dir_path = os.path.dirname(principal)
        os.makedirs(os.path.join(output_dir_path, dir_path), exist_ok=True)
        # Add account info to each file
        out_dict = {
            'vulnerable_principal':src_principal,
            'reachable_admin_principals':dst_list
        }
        # Create a file for each vulnerable principal
        st.dumpToJson(out_dict, '{}/{}.json'.format(output_dir_path,principal), indent=4)