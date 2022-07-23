from remediation.remediation_handler import RemediationStrategy, RemediationHandler, AWS_SVC_TYPE
import re
import logging

class LambdaHandler(RemediationHandler):
    def __init__(self) -> None:
        super().__init__(AWS_SVC_TYPE.LAMBDA)

    def get_remediation_plan(self, src_principal, dst_principal, reason):
        '''
        scenario1: iam:PassRole to lambda.amazonaws.com and lambda:CreateFunction
        scenario2: lambda:UpdateFunctionCode 
        scenario3: iam:PassRole to lambda.amazonaws.com and lambda:UpdateFunctionConfiguration and lambda:UpdateFunctionCode
        '''
        if 'can use Lambda to create a new function with arbitrary code' in reason:
            return self._plan_scenario1(src_principal, dst_principal)
        elif 'can use Lambda to edit an existing function' in reason:
            return self._plan_scenario2(src_principal, reason)
        else:
            logging.error('Unrecognized PMapper reason')

    def _plan_scenario1(self, src_principal, dst_principal):
        ''' Deny src_principal to perform iam:PassRole on dst_principal' or 'deny lambda:CreateFunction '''
        plan1 = RemediationStrategy(src_principal, 'lambda')
        action_list = ['lambda:CreateFunction']
        resource_list = ['*']
        plan1.add_process('Deny', action_list, resource_list)
        
        plan2 = RemediationStrategy(src_principal, 'lambda')
        action_list = ['iam:PassRole']
        resource_list = ['{}'.format(dst_principal)]
        plan2.add_process('Deny', action_list, resource_list)
        return [plan1, plan2]


    def _plan_scenario2(self, src_principal, reason):
        ''' deny src to perform lambda:UpdateFunctionCode on specific function '''
        # Parse the function arn 
        lambda_re = re.compile(r'.+\((arn:aws:lambda:\S+)\).+')
        search = lambda_re.search(reason)
        if search:
            lambda_arn = search.group(1).strip()

        plan1 = RemediationStrategy(src_principal, 'lambda')
        action_list = ['lambda:UpdateFunctionCode']
        resource_list = [lambda_arn]
        plan1.add_process('Deny', action_list, resource_list)

        return[plan1]


   