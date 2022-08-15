#!/usr/bin/env python3
import argparse
import sys
import boto3
import botocore
import os
import logging
import logging.config

import common.constants as CONST
import common.shared_tools as st
import main.audit as audit_aws
import main.plan as plan_desc
import main.apply as apply_plan
import main.revert as revert_plan

AWS = dict()

def audit(parsed_args):
    ''' Use PMapper to identify the principals vulnerable to priviledge escalation attacks. The result is output as a json file undert output/account_id/audit/ '''
    logging.info('Auditing AWS account {} ...'.format(AWS['account_id']))
    result = audit_aws.audit_aws(parsed_args, AWS)
    # Display
    if 'admins' in result:
        logging.info('Principals with AdministratorAccess permissions:')
        for p in result['admins']:
            logging.info('    {}'.format(p))
        logging.info('')
    else:
        logging.info('There is no principal with AdministratorAccess permissions \N{slightly smiling face}')
    if 'privesc_principal' in result:
        logging.info('Non-admin principals vulnerable to privilege escalation:')
        for principal in result['privesc_principal'].keys():
            msg = '    {}'.format(st.parse_principal_from_arn(principal))
            if principal == AWS['arn']:
                msg += ' (Caller will be excluded from the remediaton process!)'
            logging.info(msg)            

    else:
        logging.info('There is no principal with privilege escalation risk \N{slightly smiling face}')
    logging.info('\nThe audit output is stored at {}'.format(os.path.join(os.path.abspath(CONST.OUTPUT_DIR), AWS['account_id'], 'audit', CONST.AUDIT_FILE)))        
    logging.info('You can exclude specific principals from the remediation process by removing them from the \"privesc_principal\" block.\n')

def plan_remediation(is_auto = False):
    ''' Read the audit output and create an output strategy for each vulnerable principal. The proposed remediation strategies are output to output/account_id/plan'''
    audit_file_path = os.path.join(CONST.OUTPUT_DIR, AWS['account_id'], 'audit', CONST.AUDIT_FILE)
    output_dir_path = os.path.join(CONST.OUTPUT_DIR, AWS['account_id'], 'plan')
    logging.info('Creating remediation plans for AWS account {} ...'.format(AWS['account_id']))
    plan_desc.plan_remediation(audit_file_path, output_dir_path, AWS, is_auto = is_auto)
    logging.info('The remediation plans have been successfully created under {}/. Each file under this directory represents one vulnerable principal.'.format(os.path.join(os.path.abspath(CONST.OUTPUT_DIR), AWS['account_id'], 'plan'))) 
    logging.info('Please review the plans and mark "patch_me" to 1 for the policies to be applied.\n')

def apply_remediation():
    ''' Read the remediation plan from output/account_id/plan and apply the policies to the aws account '''
    logging.info('Applying the remediation strategy for AWS account {} ...'.format(AWS['account_id'])) 
    plan_path = os.path.join(CONST.OUTPUT_DIR, AWS['account_id'], 'plan')
    apply_plan.apply_remediation(plan_path, AWS)

def revert_remediation(is_all = False):
    ''' Read the remediation plan from output/account_id/plan and revert all the changes.'''
    logging.info('Reverting the remediation strategy previously applied to AWS account {} ...'.format(AWS['account_id'])) 
    plan_path = os.path.join(CONST.OUTPUT_DIR, AWS['account_id'], 'plan')
    revert_plan.revert_remediation(plan_path, AWS, all_principal=is_all)
    

def retrieve_aws_info(aws_profile):
    ''' Populaate profile, session, account_id, caller_arn into global variable AWS '''
    global AWS
    AWS['profile'] = aws_profile
    try:
        AWS['session'] = boto3.Session(profile_name=aws_profile)
        caller_id = AWS['session'].client('sts').get_caller_identity()
        AWS['account_id'] = caller_id['Account']
        AWS['arn'] = caller_id['Arn']
    except (botocore.exceptions.ClientError, botocore.exceptions.ProfileNotFound) as error:
        sys.exit('Invalid AWS profile {}. {}'.format(aws_profile, error))

def parseArgs():
    argument_parser = argparse.ArgumentParser()
    
    argument_parser.add_argument('--profile', help='AWS profile to use. If not provided, the default profile will be used', default=None)
    # argument_parser.add_argument('--account', help='AWS account id. If not provided, the default profile\`s account ID will be used', default=None)

    # Create subparser for various subcommands
    subparser = argument_parser.add_subparsers(
        title='subcommand',
        description='The subcommand to use among this suite of tools',
        dest='sub_cmd',
        help='Select a subcommand to execute'
    )

    # Add a subcommand
    audit_cmd_parser = subparser.add_parser(
        'audit',
         description='''Search for pricipals with privilege escalation risks. Under the hood, it models the principals as a graph using PMapper and searchs for privilege escalation paths from non-admin principals to admin principals. --principal parameter restricts the search to only the specified principals ''',
        help=''' Pull the IAM information from an AWS account and search for principals with privilege escalation risks. 
        E.g., python3 iam_desc.py --profile my_prof audit  '''       
    )    
    # Add arguments for the subcommand    
    audit_aws.provide_graph_arguments(audit_cmd_parser)

    plan_cmd_parser = subparser.add_parser(
        'plan',
        description=''' Create a remediation plan for every principal with previlege escalation risks. This command needs to be run after the audit commmand finishes. E.g., python3 iam_desc.py --profile my_prof plan ''',
        help='Use the audit result to create a remediation plan. If --auto flag is specified, the "patch_me" fields in each plan will be set to 1'
    )
    plan_cmd_parser.add_argument('--auto',  action='store_true', help='Automatically pick a remediation strategy for each vulnerable principal and marks its patch_me field as 1. This will NOT actually apply the remediation.')

    subparser.add_parser(
        'apply',
        description=''' Find the proposed remediation plans stored in ./output/AWS_ID/plan/. Each file under this directory represents a non-admin principal that can be escalated to an admin principal. A non-admin principal may be escalated to multiple admin principals. Between each non-admin principal and admin principal, there may be multiple "escalation edgess". For each escalation edgeh, the remediation plan may have multiple remediation strategy. Applying any remediation strategy can break the attack path and eliminate the risk. To manually pick the remediation strategy, set at least one "patch_me" field to 1 under each remediations block. E.g., python3 iam_desc.py --profile my_prof revert''',
        help='Apply the remediation plan.This command needs to be run after the plan commmand finishes. E.g., python3 iam_desc.py --profile my_profile apply'
    ) 

    revert_cmd_parser = subparser.add_parser(
        'revert',
        description=''' Revert the change made by the apply command. The inline policies attached to the vulnerable principals will be deleted. E.g., python3 iam_desc.py --profile my_prof revert  ''',
        help='Revert the changes made by the apply command. If --all flag is specified, IAM-Deescalate will check EVERY user and role in this account'
    )
    revert_cmd_parser.add_argument('--all', action='store_true', help='Enumerate every user and role to remove previously inserted remediation policies')
   
    main_args = argument_parser.parse_args()
    if main_args.profile:
        retrieve_aws_info(main_args.profile)
    else:
        retrieve_aws_info('default')

    if main_args.sub_cmd == 'audit':
        logging.info(CONST.BANNER)
        audit(main_args)
    elif main_args.sub_cmd == 'plan':
        plan_remediation(is_auto = main_args.auto)
    elif main_args.sub_cmd == 'apply':
        apply_remediation() 
    elif main_args.sub_cmd == 'revert':
        revert_remediation(is_all = main_args.all)    

def main():
    logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': True,
    })    
    logging.basicConfig(level=logging.INFO, format='%(message)s')    
    parseArgs()  
    

if __name__ == '__main__':
    sys.exit(main())
