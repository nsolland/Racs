"""Generate boundary-aware RACS v0.2 runtime and canonical vectors.

Run from repository root:
    python test-vectors/0.2/runtime-validation/_generate.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
OUT = REPO / "test-vectors" / "0.2"
sys.path.insert(0, str(REPO / "reference" / "bindings" / "v0.2" / "python"))
from racs_v02 import canonical_str, sha256_digest  # noqa: E402

D='sha256:'+'a'*64

def canon(o):
    return canonical_str(o)
def digest(o):
    return sha256_digest(o)
def dump(path,o):
    p=OUT/path; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(o,indent=2,ensure_ascii=False)+'\n', encoding='utf-8')

def action_envelope():
    return {
      'action_id':'act-001','tenant_id':'tenant-1','action_type':'CONNECTOR_CALL','actor_ref':'agent://demo/1',
      'target_ref':'system://demo/target','target_digest':D,'payload_digest':D,
      'authority_grant_ref':'authority://grant/001','delegation_chain_ref':'delegation://chain/001',
      'policy_ref':'policy://boundary/001','evidence_package_ref':'evidence://package/001',
      'purpose_ref':'purpose://demo/001','environment_state_ref':'state://environment/001',
      'risk_context_ref':'risk://context/001','connector_id':'conn-1','capability':'read',
      'consequence_class':'LOW','reversibility':'REVERSIBLE','created_at':'2026-07-23T11:50:00Z',
      'expires_at':'2026-07-23T12:20:00Z','replay_nonce':'0123456789abcdef0123','idempotency_key':'idem-001',
      'boundary_requirements':{'required_types':['EXECUTION'],'policy_ref':'policy://boundary/001','policy_digest':D,'fail_closed':True}
    }
AE=action_envelope(); AE_DIGEST=digest(AE)

def assessment():
    return {
      'schema_version':'racs.boundary-crossing-assessment.v0.2','assessment_id':'bca-001','action_id':'act-001',
      'action_envelope_digest':AE_DIGEST,'tenant_id':'tenant-1','assessor_id':'boundary-evaluator-1','assessor_version':'0.2.0',
      'requirement_policy_ref':'policy://boundary/001','requirement_policy_digest':D,
      'crossings':[{
        'crossing_id':'crossing-execution-001','boundary_type':'EXECUTION','crossing_detected':True,
        'prior_state_digest':'sha256:'+'b'*64,'proposed_state_digest':'sha256:'+'c'*64,
        'authority_requirement_ref':'authority-requirement://execution/001',
        'authority_binding':{'ref':'authority://grant/001','digest':D},
        'policy_binding':{'ref':'policy://boundary/001','digest':D},
        'evidence_binding':{'ref':'evidence://execution/001','digest':D},
        'details_digest':'sha256:'+'d'*64,'state':'AUTHORIZED','required_response_floor':'NONE','reason_codes':[],
        'observed_at':'2026-07-23T11:55:00Z','valid_until':'2026-07-23T12:20:00Z'}],
      'aggregate_state':'AUTHORIZED','required_response_floor':'NONE','reason_codes':[],
      'assessed_at':'2026-07-23T11:55:00Z','valid_until':'2026-07-23T12:20:00Z','revocation_registry_ref':'revreg-001'
    }
BCA=assessment(); BCA_DIGEST=digest(BCA)

def ev_payload():
    return {'evaluation_id':'ev-001','action_id':'act-001','action_envelope_digest':AE_DIGEST,'tenant_id':'tenant-1','evaluator_id':'eval-1','evaluator_version':'1.0.0','decision':'ALLOW','authority_status':'PRESENT_AND_VALID','policy_status':'PRESENT_AND_VALID','evidence_status':'PRESENT_AND_VALID','purpose_status':'PRESENT_AND_VALID','state_status':'PRESENT_AND_VALID','risk_status':'PRESENT_AND_VALID','reason_codes':['OK'],'boundary_assessment_binding':{'assessment_ref':'bca-001','assessment_digest':BCA_DIGEST},'evaluated_at':'2026-07-23T12:00:00Z','valid_until':'2026-07-23T12:18:00Z'}
EV=ev_payload(); EV_DIGEST=digest(EV)
def det_payload():
    return {'determination_id':'det-001','action_id':'act-001','action_envelope_digest':AE_DIGEST,'tenant_id':'tenant-1','authority_digest':D,'delegation_chain_digest':D,'policy_digest':D,'evidence_digest':D,'purpose_digest':D,'state_digest':D,'evaluation_bindings':[{'evaluation_ref':'ev-001','evaluation_digest':EV_DIGEST}],'boundary_assessment_binding':{'assessment_ref':'bca-001','assessment_digest':BCA_DIGEST},'state':'ADMISSIBLE','reason_codes':['OK'],'determined_at':'2026-07-23T12:05:00Z','valid_until':'2026-07-23T12:16:00Z','revocation_registry_ref':'revreg-001'}
DET=det_payload(); DET_DIGEST=digest(DET)
def clr_payload():
    return {'clearance_id':'clr-001','action_id':'act-001','action_envelope_digest':AE_DIGEST,'tenant_id':'tenant-1','decision':'ALLOW','admissibility_state':'ADMISSIBLE','authority_digest':D,'delegation_chain_digest':D,'policy_digest':D,'evidence_digest':D,'purpose_digest':D,'state_digest':D,'target_digest':D,'payload_digest':D,'connector_id':'conn-1','capability':'read','consequence_class':'LOW','reversibility':'REVERSIBLE','valid_from':'2026-07-23T12:10:00Z','valid_until':'2026-07-23T12:15:00Z','replay_nonce':'0123456789abcdef0123','idempotency_key':'idem-001','revocation_registry_ref':'revreg-001','evaluator_refs':['eval-1'],'admissibility_determination_ref':'det-001','admissibility_determination_digest':DET_DIGEST}
VERIFICATION_TIME='2026-07-23T12:12:00Z'

def vec(id,atype,expected,reason,payload,resolved=None,vt=None):
    x={'id':id,'artifact_type':atype,'expected':expected,'reason_code':reason,'payload':payload}
    if vt:x['verification_time']=vt
    if resolved:x['resolved']=resolved
    return x
# schema vectors
vectors=[]
vectors.append(('governance-evaluation/ev_accept.json',vec('ev_accept','GovernanceEvaluation','ACCEPT','ACCEPT',ev_payload())))
e=ev_payload();e['decision']='NOT_A_DECISION';vectors.append(('governance-evaluation/ev_reject_bad_enum.json',vec('ev_reject_bad_enum','GovernanceEvaluation','REJECT','SCHEMA_INVALID',e)))
e=ev_payload();del e['evaluator_id'];vectors.append(('governance-evaluation/ev_reject_missing_required.json',vec('ev_reject_missing_required','GovernanceEvaluation','REJECT','SCHEMA_INVALID',e)))
e=ev_payload();e['action_envelope_digest']='not-a-digest';vectors.append(('governance-evaluation/ev_reject_bad_digest_pattern.json',vec('ev_reject_bad_digest_pattern','GovernanceEvaluation','REJECT','SCHEMA_INVALID',e)))
vectors.append(('admissibility-determination/det_accept.json',vec('det_accept','AdmissibilityDetermination','ACCEPT','ACCEPT',det_payload())))
d=det_payload();d['evaluation_bindings']=[];vectors.append(('admissibility-determination/det_reject_empty_bindings.json',vec('det_reject_empty_bindings','AdmissibilityDetermination','REJECT','SCHEMA_INVALID',d)))
d=det_payload();d['state']='WRONG_STATE';vectors.append(('admissibility-determination/det_reject_bad_state_enum.json',vec('det_reject_bad_state_enum','AdmissibilityDetermination','REJECT','SCHEMA_INVALID',d)))
vectors.append(('governance-clearance/clr_allow_accept.json',vec('clr_allow_accept','GovernanceClearance','ACCEPT','ACCEPT',clr_payload())))
c=clr_payload();c['constraints']={'machine_readable':True,'binds_exact_action':True,'rules':[{'id':'r1','predicate':'max','target':'x','value':5}]};vectors.append(('governance-clearance/clr_allow_with_constraints.json',vec('clr_allow_with_constraints','GovernanceClearance','REJECT','SCHEMA_INVALID',c)))
c=clr_payload();c['decision']='MODIFY';c['admissibility_state']='CONDITIONALLY_ADMISSIBLE';vectors.append(('governance-clearance/clr_modify_missing_constraints.json',vec('clr_modify_missing_constraints','GovernanceClearance','REJECT','SCHEMA_INVALID',c)))
c=clr_payload();c['admissibility_state']='CONDITIONALLY_ADMISSIBLE';vectors.append(('governance-clearance/clr_allow_state_mismatch.json',vec('clr_allow_state_mismatch','GovernanceClearance','REJECT','SCHEMA_INVALID',c)))
c=clr_payload();c['replay_nonce']='short';vectors.append(('governance-clearance/clr_reject_short_nonce.json',vec('clr_reject_short_nonce','GovernanceClearance','REJECT','SCHEMA_INVALID',c)))
resolved={'action_envelope':AE,'boundary_assessment':BCA,'evaluation':EV,'determination':DET}
vectors.append(('cross-artifact-bindings/chain_accept.json',vec('chain_accept','GovernanceClearance','ACCEPT','ACCEPT',clr_payload(),resolved,VERIFICATION_TIME)))
c=clr_payload();c['admissibility_determination_digest']='sha256:'+'0'*64;vectors.append(('cross-artifact-bindings/chain_reject_det_digest_mismatch.json',vec('chain_reject_det_digest_mismatch','GovernanceClearance','REJECT','CLEARANCE_DETERMINATION_DIGEST_MISMATCH',c,resolved,VERIFICATION_TIME)))
d=det_payload();d['evaluation_bindings']=[{'evaluation_ref':'ev-001','evaluation_digest':'sha256:'+'0'*64}];r={**resolved,'determination':d}; c=clr_payload(); c['admissibility_determination_digest']=digest(d);vectors.append(('cross-artifact-bindings/chain_reject_eval_binding_mismatch.json',vec('chain_reject_eval_binding_mismatch','GovernanceClearance','REJECT','EVALUATION_BINDING_DIGEST_MISMATCH',c,r,VERIFICATION_TIME)))
# boundary chain negatives
r={**resolved}; r['boundary_assessment']=dict(BCA); r['boundary_assessment']['requirement_policy_digest']='sha256:'+'0'*64
# binding must match mutated assessment digest, so gets to policy check
r['evaluation']=dict(EV); r['evaluation']['boundary_assessment_binding']={'assessment_ref':'bca-001','assessment_digest':digest(r['boundary_assessment'])}
r['determination']=dict(DET); r['determination']['boundary_assessment_binding']=r['evaluation']['boundary_assessment_binding']; r['determination']['evaluation_bindings']=[{'evaluation_ref':'ev-001','evaluation_digest':digest(r['evaluation'])}]
c=clr_payload();c['admissibility_determination_digest']=digest(r['determination'])
vectors.append(('cross-artifact-bindings/chain_reject_boundary_policy_mismatch.json',vec('chain_reject_boundary_policy_mismatch','GovernanceClearance','REJECT','BOUNDARY_POLICY_MISMATCH',c,r,VERIFICATION_TIME)))
e=ev_payload(); del e['boundary_assessment_binding']; vectors.append(('governance-evaluation/ev_reject_missing_boundary_binding.json',vec('ev_reject_missing_boundary_binding','GovernanceEvaluation','REJECT','SCHEMA_INVALID',e)))
d=det_payload(); del d['boundary_assessment_binding']; vectors.append(('admissibility-determination/det_reject_missing_boundary_binding.json',vec('det_reject_missing_boundary_binding','AdmissibilityDetermination','REJECT','SCHEMA_INVALID',d)))
for p,o in vectors: dump(Path('runtime-validation')/p,o)
# boundary canonical file
boundary_canonical={'schema_version':'racs.boundary-crossing-vectors.v0.2','vectors':[{'id':'boundary_assessment_authorized_execution','artifact_type':'BoundaryCrossingAssessment','payload':BCA,'canonical_payload':canon(BCA),'payload_digest':BCA_DIGEST},{'id':'governance_evaluation_bound_to_assessment','artifact_type':'GovernanceEvaluation','payload':EV,'canonical_payload':canon(EV),'payload_digest':EV_DIGEST},{'id':'admissibility_determination_preserves_assessment','artifact_type':'AdmissibilityDetermination','payload':DET,'canonical_payload':canon(DET),'payload_digest':DET_DIGEST}], 'chain_invariants':['assessment is evidence, never authority','execution boundary is always declared','evaluation and determination bind the exact assessment digest','determination cannot outlive evaluation or assessment']}
dump(Path('boundary-crossing/canonical-vectors.json'),boundary_canonical)
# golden evaluation based on deterministic actual assessment binding
GOLD_BCA=dict(BCA); GOLD_BCA['assessment_id']='bca:gv_allow'; GOLD_BCA['action_id']='act_test_001'; GOLD_BCA['action_envelope_digest']=D; GOLD_BCA['tenant_id']='tenant-test'; GOLD_BCA['assessed_at']='2026-07-14T17:55:00Z'; GOLD_BCA['valid_until']='2026-07-14T18:10:00Z'; GOLD_BCA['crossings']=[dict(BCA['crossings'][0])]; GOLD_BCA['crossings'][0]['crossing_id']='crossing:gv_allow:execution'; GOLD_BCA['crossings'][0]['observed_at']='2026-07-14T17:55:00Z'; GOLD_BCA['crossings'][0]['valid_until']='2026-07-14T18:10:00Z'; GOLD_BCA_DIGEST=digest(GOLD_BCA)
GOLD_EV={'action_envelope_digest':D,'action_id':'act_test_001','authority_status':'PRESENT_AND_VALID','boundary_assessment_binding':{'assessment_ref':'bca:gv_allow','assessment_digest':GOLD_BCA_DIGEST},'decision':'ALLOW','evaluated_at':'2026-07-14T18:00:00Z','evaluation_id':'vaig:gv_allow','evaluator_id':'vaig:test','evaluator_version':'0.2','evidence_status':'PRESENT_AND_VALID','policy_status':'PRESENT_AND_VALID','purpose_status':'PRESENT_AND_VALID','reason_codes':['aarm.allow'],'risk_status':'PRESENT_AND_VALID','state_status':'PRESENT_AND_VALID','tenant_id':'tenant-test','valid_until':'2026-07-14T18:05:00Z'}
GOLD_EV_DIGEST=digest(GOLD_EV)
golden={'canonical_payload':canon(GOLD_EV),'description':'Golden GovernanceEvaluation (ALLOW) bound to the exact BoundaryCrossingAssessment digest.','payload':GOLD_EV,'payload_digest':GOLD_EV_DIGEST,'vector_id':'gev_allow'}
dump(Path('governance-evaluation-golden.json'),golden)
jcs_path = REPO / 'test-vectors' / 'jcs' / 'racs-v0.2' / 'governance-evaluation.json'
jcs_path.write_text(json.dumps({'vector_id':'gev_allow_rfc8785','description':'RACS GovernanceEvaluation (ALLOW) with mandatory BoundaryCrossingAssessment binding.','payload':GOLD_EV,'canonical_payload':canon(GOLD_EV),'payload_digest':GOLD_EV_DIGEST}, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps({'AE_DIGEST':AE_DIGEST,'BCA_DIGEST':BCA_DIGEST,'EV_DIGEST':EV_DIGEST,'DET_DIGEST':DET_DIGEST,'GOLD_BCA_DIGEST':GOLD_BCA_DIGEST,'GOLD_EV_DIGEST':GOLD_EV_DIGEST,'vectors':len(vectors)},indent=2))
