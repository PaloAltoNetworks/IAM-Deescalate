
from remediation.remediation_handler import RemediationStrategy, RemediationHandler, AWS_SVC_TYPE
import logging

class SagemakerHandler(RemediationHandler):
    def __init__(self) -> None:
        super().__init__(AWS_SVC_TYPE.SAGEMAKER)

    def get_remediation_plan(self, src_principal, dst_principal, reason):
        if 'can use SageMaker to launch a notebook and access' in reason:
            return self._plan_scenario1(src_principal, dst_principal)
        elif 'can use SageMaker to create a training job and access' in reason:
            return self._plan_scenario2(src_principal, dst_principal)
        elif 'can use SageMaker to create a processing job and access' in reason:
            return self._plan_scenario3(src_principal, dst_principal)
        else:
            logging.error('Unrecognized PMapper reason {}'.format(reason))

    def _plan_scenario1(self, src_principal, dst_principal):
        ''' deny src to perform iam:PassRole on dst or 'deny sagemaker:CreateNotebookInstance '''
        strategy1 = RemediationStrategy(src_principal, 'sagemaker')
        action_list = ['iam:PassRole']
        resource_list = ['{}'.format(dst_principal)]
        strategy1.add_process('Deny', action_list, resource_list)
        
        strategy2 = RemediationStrategy(src_principal, 'sagemaker')
        action_list = ['sagemaker:CreateNotebookInstance']
        resource_list = ['*']
        strategy2.add_process('Deny', action_list, resource_list)
        return [strategy1, strategy2]


    def _plan_scenario2(self, src_principal, dst_principal):
        ''' deny src to perform iam:PassRole on dst or 'deny sagemaker:CreateTrainingJob '''
        strategy1 = RemediationStrategy(src_principal, 'sagemaker')
        action_list = ['iam:PassRole']
        resource_list = ['{}'.format(dst_principal)]
        strategy1.add_process('Deny', action_list, resource_list)
        
        strategy2 = RemediationStrategy(src_principal, 'sagemaker')
        action_list = ['sagemaker:CreateTrainingJob']
        resource_list = ['*']
        strategy2.add_process('Deny', action_list, resource_list)
        return [strategy1, strategy2]

    def _plan_scenario3(self, src_principal, dst_principal):
        ''' deny src to perform iam:PassRole on dst or 'deny sagemaker:CreateProcessingJob '''
        strategy1 = RemediationStrategy(src_principal, 'sagemaker')
        action_list = ['iam:PassRole']
        resource_list = ['{}'.format(dst_principal)]
        strategy1.add_process('Deny', action_list, resource_list)
        
        strategy2 = RemediationStrategy(src_principal, 'sagemaker')
        action_list = ['sagemaker:CreateProcessingJob']
        resource_list = ['*']
        strategy2.add_process('Deny', action_list, resource_list)
        return [strategy1, strategy2]