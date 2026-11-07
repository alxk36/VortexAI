// Compatibility view of the team's prompts/00-shared-contract.md Finding schema.
// Dashboard findings stay compact; this export preserves independent sources and
// blocked attempts without treating a blocked attempt as an exploitable weakness.
const TAXONOMY = {
  storagePrivate:{technique:'public_bucket',category:2},
  requireMfa:{technique:'password_spray',category:1},
  databaseLeastPrivilege:{technique:'overpermissive_iam',category:2},
};
// Build an export view without changing dashboard findings. Attacker attempts
// come from the rolling feed; retained Searcher evidence may outlive that feed.
export function sharedFindings(snapshot,envId='local-lab') {
  const searcher=snapshot.findings.map(f=>({
    id:f.id,source:'searcher',origin:'internal',...TAXONOMY[f.policyKey],resource_id:f.nodeId,env_id:envId,
    severity:f.severity,title:f.title,evidence:{path:`events[${f.evidence.join(',')}]`,value:f.evidenceDetails},
    exploited:null,detected:null,attack_run_id:null,
    // Additive fields retain dashboard linkage while leaving the shared fields intact.
    status:f.status,evidenceIds:f.evidence,recommendationId:f.recommendationId,
  }));
  const attempts=snapshot.events.filter(e=>e.kind!=='normal' && TAXONOMY[e.control] && ['list-objects','read-object','sign-in','admin-export'].includes(e.action));
  const attacker=attempts.map(e=>({
    id:`attempt-${e.id}`,source:'attacker',origin:'external',...TAXONOMY[e.control],resource_id:e.target,env_id:envId,
    severity:e.control==='requireMfa'?'high':'critical',title:`${e.action}: ${e.outcome}`,
    evidence:{path:`events[${e.id}]`,value:e},exploited:e.outcome==='allowed',detected:true,attack_run_id:e.runId || null,
    status:e.outcome==='allowed'?'proven':'defended',evidenceIds:[e.id],recommendationId:`recommendation-${e.control}`,
  }));
  return structuredClone([...searcher,...attacker]);
}
