from remediation.remediation_handler import RemediationStrategy, RemediationHandler, AWS_SVC_TYPE
import logging

class AutoscalHandler(RemediationHandler):
    def __init__(self) -> None:
        super().__init__(AWS_SVC_TYPE.AUTOSCALING)

    
    def get_remediation_plan(self, src_principal, dst_principal, reason):
        if 'can use the EC2 Auto Scaling service role and an existing Launch Configuration to access' in reason or 'can create the EC2 Auto Scaling service role and an existing Launch Configuration to access' in reason:
            return self._plan_scenario1(src_principal)
        elif 'create a launch configuration to access' in reason:
            return self._plan_scenario2(src_principal, dst_principal)
        else:
            logging.error('Unrecognized PMapper reason')

    def _plan_scenario1(self, src_principal):
        ''' Deny src_principal to perform autoscaling:CreateAutoScalingGroup '''
        plan = RemediationStrategy(src_principal, 'autoscaling')
        action_list = ['autoscaling:CreateAutoScalingGroup']
        resource_list = ['*']
        plan.add_process('Deny', action_list, resource_list)
        return [plan]


    def _plan_scenario2(self, src_principal, dst_principal):
        ''' deny src_principal to perform autoscaling:CreateLaunchConfiguration or deny src_principal to perform iam:PassRole dst on ec2.amazonaws.com '''
        plan1 = RemediationStrategy(src_principal, 'autoscaling')
        action_list = ['autoscaling:CreateLaunchConfiguration']
        resource_list = ['*']
        plan1.add_process('Deny', action_list, resource_list)

        plan2 = RemediationStrategy(src_principal, 'autoscaling')
        action_list = ['iam:PassRole']
        resource_list = ['{}'.format(dst_principal)]
        plan2.add_process('Deny', action_list, resource_list)

        return[plan1, plan2]

