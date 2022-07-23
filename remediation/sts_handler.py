
import logging
from remediation.remediation_handler import RemediationStrategy, RemediationHandler, AWS_SVC_TYPE

class STSHandler(RemediationHandler):
    def __init__(self) -> None:
        super().__init__(AWS_SVC_TYPE.STS)

    def get_remediation_plan(self, src_principal, dst_principal, reason):
        '''
        condition1: sts:AssumeRole
        condition2: 
        '''
        if 'can access via sts:AssumeRole' in reason:
            return self._plan_scenario1(src_principal, dst_principal)
        else:
            logging.error('Unrecognized PMapper reason {}'.format(reason))
    
    def _plan_scenario1(self, src_principal, dst_principal):
        ''' Deny src_principal to perform autoscaling:CreateAutoScalingGroup '''
        plan = RemediationStrategy(src_principal, 'sts')
        action_list = ['sts:AssumeRole']
        resource_list = ['{}'.format(dst_principal)]
        plan.add_process('Deny', action_list, resource_list)
        return [plan] 