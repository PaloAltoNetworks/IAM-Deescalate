from remediation.remediation_handler import RemediationStrategy, RemediationHandler, AWS_SVC_TYPE
import re
import logging

class CFHandler(RemediationHandler):
    def __init__(self) -> None:
        super().__init__(AWS_SVC_TYPE.CLOUDFORMATION)

    def get_remediation_plan(self, src_principal, dst_principal, reason):
        if 'can create a stack in CloudFormation to access' in reason:
            return self._plan_scenario1(src_principal, dst_principal)
        elif 'can update the CloudFormation stack' in reason:
            return self._plan_scenario2(src_principal, reason)
        elif 'can create and execute a changeset in CloudFormation for stack' in reason:
            return self._plan_scenario3(src_principal, reason)
        else:
            logging.error('Unrecognized PMapper reason')

    def _plan_scenario1(self, src_principal, dst_principal):
        ''' Deny src_principal to perform cloudformation:CreateStack or deny src_principal to perform iam:PassRole on dst_principal '''
        strategy1 = RemediationStrategy(src_principal, 'cloudformation')
        action_list = ['cloudformation:CreateStack']
        resource_list = ['*']
        strategy1.add_process('Deny', action_list, resource_list)
        
        strategy2 = RemediationStrategy(src_principal, 'cloudformation')
        action_list = ['iam:PassRole']
        resource_list = ['{}'.format(dst_principal)]
        strategy2.add_process('Deny', action_list, resource_list)
        return [strategy1, strategy2]


    def _plan_scenario2(self, src_principal, reason):
        ''' Deny src_principal to perform cloudformation:UpdateStack on a specific stack '''
        # Parse the function arn 
        cf_re = re.compile(r'.+(arn:aws:cloudformation:\S+).+')
        search = cf_re.search(reason)
        if search:
            cf_arn = search.group(1).strip()

        strategy1 = RemediationStrategy(src_principal, 'cloudformation')
        action_list = ['cloudformation:UpdateStack']
        resource_list = [cf_arn]
        strategy1.add_process('Deny', action_list, resource_list)

        return[strategy1]

    def _plan_scenario3(self, src_principal, reason):
        ''' Deny src_principal to perform cloudformation:ExecuteChangeSet on specific stack '''
        # Parse the function arn 
        cf_re = re.compile(r'.+(arn:aws:cloudformation:\S+).+')
        search = cf_re.search(reason)
        if search:
            cf_arn = search.group(1).strip()

        strategy1 = RemediationStrategy(src_principal, 'cloudformation')
        action_list = ['cloudformation:ExecuteChangeSet']
        resource_list = [cf_arn]
        strategy1.add_process('Deny', action_list, resource_list)

        return[strategy1]


