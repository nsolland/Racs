export type BoundaryType =
  | "EXECUTION" | "DISCLOSURE" | "MANDATE" | "RESOURCE" | "EVALUATION";

export type BoundaryState =
  | "NO_CROSSING" | "AUTHORIZED" | "CONDITIONALLY_AUTHORIZED"
  | "UNAUTHORIZED" | "INDETERMINATE" | "STALE" | "REVOKED";

export type BoundaryResponseFloor =
  | "NONE" | "MODIFY" | "DEFER" | "STEP_UP" | "DENY" | "HALT";

export interface ArtifactBinding {
  ref: string;
  digest: string;
}

export interface BoundaryAssessmentBinding {
  assessment_ref: string;
  assessment_digest: string;
}

export interface BoundaryRequirementSet {
  required_types: BoundaryType[];
  policy_ref: string;
  policy_digest: string;
  fail_closed: true;
}

export interface BoundaryCrossing {
  crossing_id: string;
  boundary_type: BoundaryType;
  crossing_detected: boolean;
  prior_state_digest: string;
  proposed_state_digest: string;
  authority_requirement_ref: string;
  authority_binding?: ArtifactBinding;
  policy_binding: ArtifactBinding;
  evidence_binding: ArtifactBinding;
  resource_reservation_binding?: ArtifactBinding;
  evaluation_provenance_binding?: ArtifactBinding;
  details_digest: string;
  state: BoundaryState;
  required_response_floor: BoundaryResponseFloor;
  reason_codes: string[];
  observed_at: string;
  valid_until: string;
}

export class BoundaryCrossingAssessment {
  schema_version!: "racs.boundary-crossing-assessment.v0.2";
  assessment_id!: string;
  action_id!: string;
  action_envelope_digest!: string;
  tenant_id!: string;
  assessor_id!: string;
  assessor_version!: string;
  requirement_policy_ref!: string;
  requirement_policy_digest!: string;
  crossings!: BoundaryCrossing[];
  aggregate_state!: BoundaryState;
  required_response_floor!: BoundaryResponseFloor;
  reason_codes!: string[];
  assessed_at!: string;
  valid_until!: string;
  revocation_registry_ref!: string;
}

const BOUNDARY_ORDER: Record<BoundaryType, number> = {
  EXECUTION: 0, DISCLOSURE: 1, MANDATE: 2, RESOURCE: 3, EVALUATION: 4,
};
const STATE_RANK: Record<BoundaryState, number> = {
  NO_CROSSING: 0, AUTHORIZED: 1, CONDITIONALLY_AUTHORIZED: 2,
  INDETERMINATE: 3, UNAUTHORIZED: 4, STALE: 5, REVOKED: 6,
};
const RESPONSE_RANK: Record<BoundaryResponseFloor, number> = {
  NONE: 0, MODIFY: 1, DEFER: 2, STEP_UP: 3, DENY: 4, HALT: 5,
};

function validTime(value: string): number {
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed) || !/(Z|[+-]\d\d:\d\d)$/.test(value)) {
    throw new Error("timestamp must include timezone");
  }
  return parsed;
}

function uniqueSorted(values: string[]): boolean {
  return new Set(values).size === values.length &&
    values.every((value, index) => index === 0 || values[index - 1] <= value);
}

function crossingSemanticError(crossing: BoundaryCrossing): string | null {
  const observed = validTime(crossing.observed_at);
  const until = validTime(crossing.valid_until);
  if (until <= observed) return "crossing valid_until must be after observed_at";
  if (!uniqueSorted(crossing.reason_codes)) return "reason_codes must be unique and sorted";

  const changed = crossing.prior_state_digest !== crossing.proposed_state_digest;
  if (crossing.crossing_detected !== changed) {
    return "crossing_detected must equal state-digest change";
  }
  if (!crossing.crossing_detected) {
    if (crossing.state !== "NO_CROSSING") return "non-crossing must use NO_CROSSING";
    if (crossing.required_response_floor !== "NONE") return "non-crossing must use NONE response";
    if (crossing.reason_codes.length > 0) return "non-crossing cannot carry reason codes";
    return null;
  }
  if (crossing.state === "NO_CROSSING") return "detected crossing cannot use NO_CROSSING";
  if (
    (crossing.state === "AUTHORIZED" || crossing.state === "CONDITIONALLY_AUTHORIZED") &&
    crossing.authority_binding === undefined
  ) {
    return "authorized crossing requires authority_binding";
  }

  const minimumByState: Record<Exclude<BoundaryState, "NO_CROSSING">, BoundaryResponseFloor> = {
    AUTHORIZED: "NONE",
    CONDITIONALLY_AUTHORIZED: "MODIFY",
    INDETERMINATE: "DEFER",
    UNAUTHORIZED: "DENY",
    STALE: "DEFER",
    REVOKED: "DENY",
  };
  const minimum = minimumByState[crossing.state as Exclude<BoundaryState, "NO_CROSSING">];
  if (RESPONSE_RANK[crossing.required_response_floor] < RESPONSE_RANK[minimum]) {
    return `${crossing.state} requires ${minimum} or stronger response`;
  }
  if (crossing.state === "AUTHORIZED" && crossing.required_response_floor !== "NONE") {
    return "AUTHORIZED crossing must use NONE response";
  }
  if (
    crossing.state === "CONDITIONALLY_AUTHORIZED" &&
    crossing.required_response_floor !== "MODIFY"
  ) {
    return "CONDITIONALLY_AUTHORIZED crossing must use MODIFY response";
  }

  const reasons = new Set(crossing.reason_codes);
  if (reasons.has("TECHNICAL_ACCESS_ONLY")) {
    if (crossing.state !== "UNAUTHORIZED") {
      return "technical access alone cannot authorize execution";
    }
    if (
      crossing.required_response_floor !== "DENY" &&
      crossing.required_response_floor !== "HALT"
    ) {
      return "technical access alone requires DENY or HALT";
    }
  }
  if (reasons.has("UNAUTHORIZED_DISCOVERABILITY") && crossing.state !== "UNAUTHORIZED") {
    return "unauthorized discoverability must be UNAUTHORIZED";
  }
  if (reasons.has("RESOURCE_LIMIT_EXCEEDED") && crossing.state !== "UNAUTHORIZED") {
    return "resource limit exceeded must be UNAUTHORIZED";
  }
  if (
    crossing.boundary_type === "RESOURCE" &&
    (crossing.state === "AUTHORIZED" || crossing.state === "CONDITIONALLY_AUTHORIZED") &&
    crossing.resource_reservation_binding === undefined
  ) {
    return "authorized resource crossing requires reservation binding";
  }
  if (
    crossing.boundary_type === "EVALUATION" &&
    crossing.evaluation_provenance_binding === undefined
  ) {
    return "evaluation crossing requires provenance binding";
  }
  return null;
}

export function boundaryAssessmentSemanticError(
  assessment: BoundaryCrossingAssessment,
): string | null {
  const assessed = validTime(assessment.assessed_at);
  const validUntil = validTime(assessment.valid_until);
  if (validUntil <= assessed) return "assessment valid_until must be after assessed_at";

  const types = assessment.crossings.map((item) => item.boundary_type);
  if (new Set(types).size !== types.length) return "assessment cannot repeat boundary types";
  if (!types.every((type, index) => index === 0 ||
      BOUNDARY_ORDER[types[index - 1]] <= BOUNDARY_ORDER[type])) {
    return "crossings must use canonical boundary order";
  }
  if (!types.includes("EXECUTION")) return "assessment must include EXECUTION boundary";

  const ids = assessment.crossings.map((item) => item.crossing_id);
  if (new Set(ids).size !== ids.length) return "crossing_id values must be unique";

  for (const crossing of assessment.crossings) {
    const error = crossingSemanticError(crossing);
    if (error) return error;
    if (crossing.policy_binding.ref !== assessment.requirement_policy_ref) {
      return "crossing policy ref must match requirement policy";
    }
    if (crossing.policy_binding.digest !== assessment.requirement_policy_digest) {
      return "crossing policy digest must match requirement policy";
    }
    if (validTime(crossing.observed_at) > assessed) {
      return "crossing cannot be observed after assessment";
    }
    if (validTime(crossing.valid_until) < validUntil) {
      return "assessment cannot outlive crossing evidence";
    }
  }

  const expectedState = assessment.crossings.reduce(
    (left, right) => STATE_RANK[left.state] >= STATE_RANK[right.state] ? left : right,
  ).state;
  const expectedResponse = assessment.crossings.reduce(
    (left, right) =>
      RESPONSE_RANK[left.required_response_floor] >= RESPONSE_RANK[right.required_response_floor]
        ? left : right,
  ).required_response_floor;
  const expectedReasons = [...new Set(
    assessment.crossings.flatMap((item) => item.reason_codes),
  )].sort();

  if (assessment.aggregate_state !== expectedState) {
    return "aggregate_state does not match crossings";
  }
  if (assessment.required_response_floor !== expectedResponse) {
    return "required_response_floor does not match crossings";
  }
  if (JSON.stringify(assessment.reason_codes) !== JSON.stringify(expectedReasons)) {
    return "assessment reason_codes must equal sorted crossing union";
  }
  return null;
}

export function responseFloorSatisfied(
  responseFloor: BoundaryResponseFloor,
  decision: string,
): boolean {
  const allowed: Record<BoundaryResponseFloor, Set<string>> = {
    NONE: new Set(["ALLOW", "MODIFY", "DEFER", "STEP_UP", "DENY", "HALT"]),
    MODIFY: new Set(["MODIFY", "DEFER", "STEP_UP", "DENY", "HALT"]),
    DEFER: new Set(["DEFER", "STEP_UP", "DENY", "HALT"]),
    STEP_UP: new Set(["STEP_UP", "DENY", "HALT"]),
    DENY: new Set(["DENY", "HALT"]),
    HALT: new Set(["HALT"]),
  };
  return allowed[responseFloor].has(decision);
}
