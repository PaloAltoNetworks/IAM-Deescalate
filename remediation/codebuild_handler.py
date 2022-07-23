from remediation.remediation_handler import RemediationStrategy, RemediationHandler, AWS_SVC_TYPE
import logging

class CodebuildHandler(RemediationHandler):
    def __init__(self) -> None:
        super().__init__(AWS_SVC_TYPE.CODEBUILD)


    def get_remediation_plan(self, src_principal, dst_principal, reason):
        if 'can use CodeBuild with an existing project to access' in reason or 'can create a project in CodeBuild to access' in reason or 'can update a project in CodeBuild to access' in reason:
            return self._plan_scenario1(src_principal)
        else:
            logging.error('Unrecognized PMapper reason')

    def _plan_scenario1(self, src_principal):
        strategy1 = RemediationStrategy(src_principal, 'codebuild')
        action_list = ['codebuild:StartBuild', 'codebuild:StartBuildBatch']
        resource_list = ['*']
        strategy1.add_process('Deny', action_list, resource_list)
        return[strategy1]

    