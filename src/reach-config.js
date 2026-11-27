'use strict';
module.exports = {
  prefix: 'zovoOpa',
  triesKey: 'zovoOpa.proTrial',
  slot: '#protools',
  tools: [
    { id: 'auditPolicy', title: 'Audit Rego fail-open and policy rules', command: 'zovoOpa.auditPolicy' },
    { id: 'diffPolicies', title: 'Compare two Rego policy files', command: 'zovoOpa.diffPolicies' },
    { id: 'exportRuleDocs', title: 'Export rule and input-path catalog', command: 'zovoOpa.exportRuleDocs' },
  ],
};
