from abc import ABC, abstractmethod
from enum import Enum
from typing import List
import logging

class AWS_SVC_TYPE(Enum):
    AUTOSCALING = 'autoscaling'
    CLOUDFORMATION = 'cloudformation'
    CODEBUILD = 'cloudbuild'
    IAM = 'iam'
    EC2 = 'ec2'
    LAMBDA = 'lambda'
    SAGEMAKER = 'sagemaker'
    SSM = 'ssm'
    STS = 'sts'

class RemediationStrategy(object):
    ''' A remediation strategy breaks one edge on a privilege escalation path. It creates a remediation plan based on the reason stored in PMapper's edge object. 
        Reference: https://github.com/nccgroup/PMapper/tree/master/principalmapper/graphing.  ''' 

    def __init__(self, principal, target_service) -> None:
        self.principal = principal
        self.service = target_service
        self.process_list = list()   # A list of processes that all should be performed to complete a strategy.  
    
    def add_process(self, effect, action_list, resource_list, condition_list = None):
        ''' Add one process necessary to break an edge. Multiple processes may be added to each strategy. To break the edge, all the processes need to be taken. '''
        process = dict()
        if not effect in ['Allow', 'Deny']:
            raise ValueError('Invalid effect. Only Allow or Deny is allowed')
        process['Effect'] = effect
        process['Action'] = action_list
        process['Resource'] = resource_list
        if condition_list:
            process['Condition'] = condition_list
        self.process_list.append(process)       

    def describe_strategy(self):
        str = ''
        for process in self.process_list:
            str += 'Effect: {}\n'.format(process['Effect'])
            str += 'Action: {}\n'.format(','.join(process['Action']))
            str += 'Resource: {}\n'.format(','.join(process['Resource']))
            if 'Condition' in process:
                str += 'Condition: {}\n'.format(','.join(process['Condition']))
            str += '\n'
        return str

    def to_policy_obj(self):
        ''' Return an AWS policy document '''
        policy = dict()
        policy['Version'] = '2012-10-17'
        policy['Statement'] = self.process_list
        return policy

class RemediationHandler(ABC):
    ''' Each subclass of RemediationHandler is an analyzer that parses the privilege escalation reasons of a specific service. Each PMapper's edge object has a reason property that explains how one node (principal) can transition to another node (principal). RemediationHander outputs a RemediationStrategy after analyzing the reasons. '''
    def __init__(self, svc_type) -> None:
        if not isinstance(svc_type, AWS_SVC_TYPE):
            logging.error('svc_type must be of type AWS_SVC_TYPE')
            raise(ValueError)

        super().__init__()

    @abstractmethod
    def get_remediation_plan(self, src_principal, dst_principal, reason) -> List[RemediationStrategy]:
        pass
        
    
