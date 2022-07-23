from remediation.remediation_handler import RemediationStrategy, RemediationHandler, AWS_SVC_TYPE
import logging

class EC2Handler(RemediationHandler):
    def __init__(self) -> None:
        super().__init__(AWS_SVC_TYPE.EC2)

    def get_remediation_plan(self, src_principal, dst_principal, reason):
        if 'can use EC2 to run an instance with' in reason:
            return self._plan_scenario1(src_principal, dst_principal)
        elif 'can use EC2 to run an instance and then' in reason:
            return self._plan_scenario2(src_principal, dst_principal)
        else:
            logging.error('Unrecognized PMapper reason {}'.format(reason))
        
    def _plan_scenario1(self, src_principal, dst_principal):
        ''' deny src to perform iam:PassRole on dst or deny src ec2:RunInstances '''
        strategy1 = RemediationStrategy(src_principal, 'ec2')
        action_list = ['iam:PassRole']
        resource_list = ['{}'.format(dst_principal)]
        strategy1.add_process('Deny', action_list, resource_list)
        
        strategy2 = RemediationStrategy(src_principal, 'ec2')
        action_list = ['ec2:RunInstances']
        resource_list = ['*']
        strategy2.add_process('Deny', action_list, resource_list)
        return [strategy1, strategy2]


    def _plan_scenario2(self, src_principal, dst_principal):
        '''  deny src to perform iam:PassRole on dst or deny src ec2:AssociateIamInstanceProfile '''
        strategy1 = RemediationStrategy(src_principal, 'ec2')
        action_list = ['iam:PassRole']
        resource_list = ['{}'.format(dst_principal)]
        strategy1.add_process('Deny', action_list, resource_list)

        strategy2 = RemediationStrategy(src_principal, 'ec2')
        action_list = ['ec2:AssociateIamInstanceProfile']
        resource_list = ['*']
        strategy2.add_process('Deny', action_list, resource_list)

        return[strategy1, strategy2]