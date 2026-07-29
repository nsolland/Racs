"""Signed, non-authority-expanding RACS runtime decisions."""
from __future__ import annotations
import json, os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping, Protocol, Sequence
import jsonschema
from racs_canonical import sha256_digest, verify_payload_digest
from racs_clearance import GovernanceClearanceVerifier
from racs_crypto import Ed25519PrivateKey, load_public_key, sign_artifact, verify_artifact_signature

_SPEC=os.path.join(os.path.dirname(__file__),"..","..","spec")
def _schema(name):
    with open(os.path.join(_SPEC,name),encoding="utf-8") as f: return json.load(f)
_ENV=_schema("canonical-artifact-envelope.schema.json"); _DEC=_schema("racs-decision-v0.2.schema.json")
_ROLE="RACS_DECISION_POINT"

class RacsDecisionError(Exception): pass
@dataclass(frozen=True)
class VerifiedClearanceChain:
    action_id:str; tenant_id:str; action_envelope_digest:str
    admissibility_determination_ref:str; admissibility_determination_digest:str
    boundary_assessment_ref:str; boundary_assessment_digest:str
    evaluation_bindings:tuple[dict[str,str],...]; valid_until:datetime
class ClearanceChainVerifier(Protocol):
    def verify(self,**kwargs)->VerifiedClearanceChain: ...

def _at(v:Any,n:str)->datetime:
    if not isinstance(v,str) or not v: raise RacsDecisionError(f"{n} is required")
    try: d=datetime.fromisoformat(v.replace("Z","+00:00"))
    except ValueError as e: raise RacsDecisionError(f"{n} is not a valid date-time") from e
    if d.tzinfo is None: raise RacsDecisionError(f"{n} must include a timezone")
    return d.astimezone(timezone.utc)
def _ts(d:datetime)->str: return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def _req(p:Mapping[str,Any],n:str):
    v=p.get(n)
    if v is None or v=="": raise RacsDecisionError(f"missing required binding: {n}")
    return v
def _constraints(v:Any)->bool:
    return isinstance(v,Mapping) and v.get("machine_readable") is True and v.get("binds_exact_action") is True and (bool(v.get("rules")) or bool(v.get("constraint_set_ref") and v.get("constraint_set_digest")))
def _narrows(up:str,down:str)->bool:
    return down in {"ALLOW":{"ALLOW","MODIFY","DEFER","DENY","STEP_UP","HALT"},"MODIFY":{"MODIFY","DEFER","DENY","STEP_UP","HALT"}}.get(up,set())
def _same_constraints(a:Any,b:Any)->bool:
    return isinstance(a,Mapping) and isinstance(b,Mapping) and sha256_digest(dict(a))==sha256_digest(dict(b))

class RacsV02ClearanceChainVerifier:
    def verify(self,*,action_envelope,boundary_assessment,governance_evaluations,admissibility_determination,governance_clearance,verification_time):
        try:
            from racs_v02 import AdmissibilityDetermination,BoundaryCrossingAssessment,GovernanceClearance,GovernanceEvaluation,verify_clearance_binding,verify_evaluation_binding
            a=BoundaryCrossingAssessment.model_validate(dict(boundary_assessment))
            es=[GovernanceEvaluation.model_validate(dict(v)) for v in governance_evaluations]
            d=AdmissibilityDetermination.model_validate(dict(admissibility_determination))
            c=GovernanceClearance.model_validate(dict(governance_clearance))
        except Exception as e: raise RacsDecisionError(f"resolved clearance chain is invalid: {e}") from e
        if not es: raise RacsDecisionError("at least one resolved GovernanceEvaluation is required")
        expected={(b.evaluation_ref,b.evaluation_digest) for b in d.evaluation_bindings}
        resolved={(e.evaluation_id,e.model_digest()) for e in es}
        if expected!=resolved: raise RacsDecisionError("resolved evaluations do not exactly match determination bindings")
        for e in es:
            r=verify_evaluation_binding(d,e,boundary_assessment=a)
            if r.decision!="ACCEPT": raise RacsDecisionError(f"evaluation binding rejected: {r.reason_code}")
            r=verify_clearance_binding(c,d,action_envelope=dict(action_envelope),verification_time=verification_time,governance_evaluation=e,boundary_assessment=a)
            if r.decision!="ACCEPT": raise RacsDecisionError(f"clearance chain rejected: {r.reason_code}")
        if c.admissibility_determination_ref!=d.determination_id or c.admissibility_determination_digest!=d.model_digest():
            raise RacsDecisionError("clearance determination digest mismatch")
        b=d.boundary_assessment_binding
        end=min(_at(action_envelope.get("expires_at"),"action_envelope.expires_at"),_at(a.valid_until,"assessment.valid_until"),_at(d.valid_until,"determination.valid_until"),_at(c.valid_until,"clearance.valid_until"),*(_at(e.valid_until,"evaluation.valid_until") for e in es))
        return VerifiedClearanceChain(d.action_id,d.tenant_id,d.action_envelope_digest,d.determination_id,d.model_digest(),b.assessment_ref,b.assessment_digest,tuple({"evaluation_ref":x.evaluation_ref,"evaluation_digest":x.evaluation_digest} for x in d.evaluation_bindings),end)

class RacsDecisionIssuer:
    def __init__(self,*,issuer_id,tenant_id,trust_domain,private_key:Ed25519PrivateKey,key_id,clearance_verifier:GovernanceClearanceVerifier,chain_verifier:ClearanceChainVerifier|None=None,profile_id="racs-platform-0.2",valid_for_seconds=30):
        if valid_for_seconds<=0: raise RacsDecisionError("valid_for_seconds must be positive")
        self.issuer_id=issuer_id; self.tenant_id=tenant_id; self.trust_domain=trust_domain; self.private_key=private_key; self.key_id=key_id; self.clearance_verifier=clearance_verifier; self.chain_verifier=chain_verifier or RacsV02ClearanceChainVerifier(); self.profile_id=profile_id; self.valid_for_seconds=valid_for_seconds
    def issue(self,*,racs_decision_id,clearance_artifact:Dict[str,Any],action_envelope,boundary_assessment,governance_evaluations,admissibility_determination,decision=None,constraints=None,reason_codes=()):
        try: self.clearance_verifier.verify(clearance_artifact)
        except Exception as e: raise RacsDecisionError(f"clearance verification failed: {e}") from e
        c=clearance_artifact["payload"]
        if clearance_artifact.get("tenant_id")!=self.tenant_id or clearance_artifact.get("trust_domain")!=self.trust_domain: raise RacsDecisionError("clearance scope does not match RACS issuer")
        now=datetime.now(timezone.utc); at=_ts(now)
        chain=self.chain_verifier.verify(action_envelope=action_envelope,boundary_assessment=boundary_assessment,governance_evaluations=governance_evaluations,admissibility_determination=admissibility_determination,governance_clearance=c,verification_time=at)
        chosen=decision or str(c.get("decision")); upstream=str(c.get("decision"))
        if not _narrows(upstream,chosen): raise RacsDecisionError("RACS decision would expand REHT clearance")
        effective=constraints if constraints is not None else (c.get("constraints") if chosen=="MODIFY" else None)
        if chosen=="MODIFY" and not _constraints(effective): raise RacsDecisionError("MODIFY requires enforceable exact-action constraints")
        if chosen!="MODIFY" and effective is not None: raise RacsDecisionError("constraints are only valid for MODIFY")
        if upstream==chosen=="MODIFY" and not _same_constraints(effective,c.get("constraints")): raise RacsDecisionError("RACS cannot replace REHT MODIFY constraints without a narrowing proof")
        if (chain.action_id,chain.tenant_id,chain.action_envelope_digest)!=(c.get("action_id"),c.get("tenant_id"),c.get("action_envelope_digest")): raise RacsDecisionError("resolved chain does not match clearance")
        if now<_at(_req(c,"valid_from"),"clearance.valid_from"): raise RacsDecisionError("REHT clearance is not yet valid")
        end=min(now+timedelta(seconds=self.valid_for_seconds),chain.valid_until,_at(_req(c,"valid_until"),"clearance.valid_until"),_at(clearance_artifact.get("expires_at"),"clearance.expires_at"))
        if end<=now: raise RacsDecisionError("resolved authorization is expired")
        p={"racs_decision_id":racs_decision_id,"action_id":chain.action_id,"tenant_id":chain.tenant_id,"action_envelope_digest":chain.action_envelope_digest,"clearance_id":_req(c,"clearance_id"),"clearance_digest":clearance_artifact["payload_digest"],"admissibility_determination_ref":chain.admissibility_determination_ref,"admissibility_determination_digest":chain.admissibility_determination_digest,"boundary_assessment_ref":chain.boundary_assessment_ref,"boundary_assessment_digest":chain.boundary_assessment_digest,"evaluation_bindings":[dict(x) for x in chain.evaluation_bindings],"decision":chosen,"connector_id":_req(c,"connector_id"),"capability":_req(c,"capability"),"target_digest":_req(c,"target_digest"),"payload_digest":_req(c,"payload_digest"),"consequence_class":_req(c,"consequence_class"),"reversibility":_req(c,"reversibility"),"reason_codes":sorted(set(reason_codes or (f"RACS_{chosen}",))),"decided_at":at,"valid_until":_ts(end),"revocation_registry_ref":_req(c,"revocation_registry_ref")}
        if effective is not None: p["constraints"]=dict(effective)
        try: jsonschema.validate(p,_DEC)
        except jsonschema.ValidationError as e: raise RacsDecisionError(f"RACS decision payload invalid: {e.message}") from e
        a={"artifact_type":"RACSDecision","schema_version":"0.2.0","profile_id":self.profile_id,"artifact_id":racs_decision_id,"tenant_id":self.tenant_id,"trust_domain":self.trust_domain,"issuer_id":self.issuer_id,"issuer_role":_ROLE,"issued_at":at,"expires_at":_ts(end),"payload":p,"payload_digest":sha256_digest(p),"canonicalization":"RACS-JCS-1","signature":{"algorithm":"Ed25519","key_id":self.key_id,"value":""}}
        sign_artifact(a,self.private_key); return a

class RacsDecisionVerifier:
    def __init__(self,trust_registry:Dict[str,Dict[str,Any]],clearance_verifier:GovernanceClearanceVerifier): self.registry=trust_registry; self.clearance_verifier=clearance_verifier
    def verify(self,a:Dict[str,Any],clearance_artifact:Dict[str,Any]):
        try: jsonschema.validate(a,_ENV); jsonschema.validate(a.get("payload",{}),_DEC)
        except jsonschema.ValidationError as e: raise RacsDecisionError(f"RACS decision schema invalid: {e.message}") from e
        p=a["payload"]
        if a.get("artifact_type")!="RACSDecision" or a.get("issuer_role")!=_ROLE: raise RacsDecisionError("artifact is not a RACSDecision")
        if a.get("artifact_id")!=p.get("racs_decision_id") or a.get("tenant_id")!=p.get("tenant_id") or not verify_payload_digest(a): raise RacsDecisionError("RACS decision envelope binding mismatch")
        e=self.registry.get(a.get("issuer_id"))
        if not e: raise RacsDecisionError(f"unknown RACS decision issuer: {a.get('issuer_id')}")
        if e.get("revocation_status")!="ACTIVE" or e.get("issuer_role")!=_ROLE or "RACSDecision" not in (e.get("allowed_artifact_types") or []): raise RacsDecisionError("RACS decision issuer is not active or authorized")
        if e.get("algorithm") not in {None,"Ed25519"} or e.get("tenant_scope")!=a.get("tenant_id") or e.get("trust_domain")!=a.get("trust_domain") or e.get("key_id")!=a.get("signature",{}).get("key_id"): raise RacsDecisionError("RACS decision issuer scope mismatch")
        key=e.get("public_key")
        if not key or not verify_artifact_signature(a,load_public_key(key.encode())): raise RacsDecisionError("RACS decision signature invalid")
        try: self.clearance_verifier.verify(clearance_artifact)
        except Exception as x: raise RacsDecisionError(f"clearance verification failed: {x}") from x
        c=clearance_artifact["payload"]
        if a.get("trust_domain")!=clearance_artifact.get("trust_domain"): raise RacsDecisionError("RACS decision trust domain mismatch")
        fields=("tenant_id","action_id","action_envelope_digest","clearance_id","admissibility_determination_ref","admissibility_determination_digest","connector_id","capability","target_digest","payload_digest","consequence_class","reversibility")
        if any(p.get(n)!=c.get(n) for n in fields) or p.get("clearance_digest")!=clearance_artifact.get("payload_digest"): raise RacsDecisionError("RACS decision clearance binding mismatch")
        up=str(c.get("decision")); down=str(p.get("decision")); cons=p.get("constraints")
        if not _narrows(up,down): raise RacsDecisionError("RACS decision expands REHT clearance")
        if down=="MODIFY" and not _constraints(cons): raise RacsDecisionError("RACS MODIFY decision lacks enforceable constraints")
        if down!="MODIFY" and cons is not None: raise RacsDecisionError("constraints are only valid for MODIFY")
        if up==down=="MODIFY" and not _same_constraints(cons,c.get("constraints")): raise RacsDecisionError("RACS decision replaced REHT MODIFY constraints without proof")
        now=datetime.now(timezone.utc); issued=_at(a.get("issued_at"),"decision.issued_at"); end=_at(p.get("valid_until"),"decision.valid_until")
        if p.get("decided_at")!=a.get("issued_at") or p.get("valid_until")!=a.get("expires_at"): raise RacsDecisionError("RACS decision time binding mismatch")
        if issued>now or issued<_at(c.get("valid_from"),"clearance.valid_from") or now>=end: raise RacsDecisionError("RACS decision is outside validity")
        if e.get("valid_from") and _at(e["valid_from"],"registry.valid_from")>issued: raise RacsDecisionError("RACS decision predates registry validity")
        if e.get("valid_until") and _at(e["valid_until"],"registry.valid_until")<=issued: raise RacsDecisionError("RACS decision issued after registry validity")
        clearance_end=min(_at(clearance_artifact.get("expires_at"),"clearance.expires_at"),_at(c.get("valid_until"),"clearance.valid_until"))
        if end>clearance_end: raise RacsDecisionError("RACS decision outlives REHT clearance")
        return p

__all__=["RacsDecisionError","VerifiedClearanceChain","ClearanceChainVerifier","RacsV02ClearanceChainVerifier","RacsDecisionIssuer","RacsDecisionVerifier"]
