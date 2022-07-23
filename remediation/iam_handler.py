from remediation.remediation_handler import RemediationStrategy, RemediationHandler, AWS_SVC_TYPE
import logging

class IAMHandler(RemediationHandler):
    def __init__(self) -> None:
        super().__init__(AWS_SVC_TYPE.IAM)

    def get_remediation_plan(self, src_principal, dst_principal, reason):
        if 'can create access keys to authenticate as' in reason:
            return self._plan_scenario1(src_principal, dst_principal)
        elif 'can set the password to authenticate as' in reason:
            return self._plan_scenario2(src_principal, dst_principal)
        elif 'can update the trust document to access' in reason:
            return self._plan_scenario3(src_principal, dst_principal)
        elif 'to escalate itself to admin' in reason:
            if 'iam:CreateRole and iam:AttachRolePolicy' in reason:
                return self._plan_scenarios(src_principal, ['iam:AttachRolePolicy'], ['iam:CreateRole'])
            elif 'iam:CreateRole and iam:PutRolePolicy' in reason:
                return self._plan_scenarios(src_principal, ['iam:PutRolePolicy'], ['iam:CreateRole'])
            elif 'iam:PutUserPolicy' in reason:
                return self._plan_scenarios(src_principal, ['iam:PutUserPolicy'])
            elif 'iam:PutRolePolicy' in reason:
                return self._plan_scenarios(src_principal, ['iam:PutRolePolicy'])
            elif 'iam:AttachUserPolicy' in reason:
                return self._plan_scenarios(src_principal, ['iam:AttachUserPolicy'])
            elif 'iam:AttachRolePolicy' in reason:
                return self._plan_scenarios(src_principal, ['iam:AttachRolePolicy'])
            elif 'iam:CreatePolicyVersion' in reason:
                return self._plan_scenarios(src_principal, ['iam:CreatePolicyVersion'])
            elif 'iam:PutGroupPolicy' in reason:
                return self._plan_scenarios(src_principal, ['iam:PutGroupPolicy'])
            elif 'iam:AttachGroupPolicy' in reason:
                return self._plan_scenarios(src_principal, ['iam:AttachGroupPolicy'])
            else:
                logging.error('Unrecognized self-escalation reason')           
        else:
            logging.error('Unrecognized PMapper reason')

    def _plan_scenario1(self, src_principal, dst_principal):
        strategy1 = RemediationStrategy(src_principal, 'iam')
        action_list = ['iam:CreateAccessKey']
        resource_list = ['{}'.format(dst_principal)]
        strategy1.add_process('Deny', action_list, resource_list)        
        return [strategy1]
    
    def _plan_scenario2(self, src_principal, dst_principal):
        strategy1 = RemediationStrategy(src_principal, 'iam')
        action_list = ['iam:CreateLoginProfile', 'iam:UpdateLoginProfile']
        resource_list = ['{}'.format(dst_principal)]
        strategy1.add_process('Deny', action_list, resource_list)        
        return [strategy1]
    
    def _plan_scenario3(self, src_principal, dst_principal):
        strategy1 = RemediationStrategy(src_principal, 'iam')
        action_list = ['iam:UpdateAssumeRolePolicy']
        resource_list = ['{}'.format(dst_principal)]
        strategy1.add_process('Deny', action_list, resource_list)        
        return [strategy1]
    
    def _plan_scenarios(self, src_principal, *action_lists):
        ''' each action_list represetns a single strategy to break the edge '''
        strategy_list = list()
        for action_list in action_lists:
            strategy = RemediationStrategy(src_principal, 'iam')
            resource_list = ['*']
            strategy.add_process('Deny', action_list, resource_list)
            strategy_list.append(strategy)
        return strategy_list
   