
from remediation.remediation_handler import RemediationStrategy, RemediationHandler, AWS_SVC_TYPE
import logging

class SSMHandler(RemediationHandler):
    def __init__(self) -> None:
        super().__init__(AWS_SVC_TYPE.SSM)

    def get_remediation_plan(self, src_principal, dst_principal, reason):
        # better if we can identify a list of instance with priviledged permissions (https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html#start-sys-console)
        if 'can call ssm:SendCommand to access an EC2' in reason:
            return self._plan_scenario1(src_principal)
        elif 'can call ssm:StartSession to access an EC2' in reason:            
            return self._plan_scenario2(src_principal)  
        else:
            logging.error('Unrecognized PMapper reason {}'.format(reason))
    
    def _plan_scenario1(self, src_principal):
        ''' deny src to perform ssm:SendCommand '''
        strategy1 = RemediationStrategy(src_principal, 'ssm')
        action_list = ['ssm:SendCommand']
        resource_list = ['*']
        strategy1.add_process('Deny', action_list, resource_list)
        return [strategy1]

    def _plan_scenario2(self, src_principal):
        ''' deny src to perform ssm:StartSession '''
        strategy1 = RemediationStrategy(src_principal, 'ssm')
        action_list = ['ssm:StartSession']
        resource_list = ['*']
        strategy1.add_process('Deny', action_list, resource_list)
        return [strategy1]