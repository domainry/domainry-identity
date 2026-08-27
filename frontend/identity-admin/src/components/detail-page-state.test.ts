import { describe, expect, it } from "vitest";
import { RuntimeApiError } from "@/lib/runtime-api";
import { detailPageStateKind, isDetailConflictError } from "./detail-page-state";

describe("detail page backend state classification", () => {
  it.each([
    [404, "backend.identity.user_not_found", "not-found"],
    [401, "auth.unauthorized", "permission-denied"],
    [403, "auth.permission_denied", "permission-denied"],
    [409, "backend.change_plan.draft_version_conflict", "conflict"],
    [412, "backend.authoring.resource_hash_mismatch", "conflict"],
    [503, "backend.runtime.unavailable", "error"],
  ] as const)("maps HTTP %s and %s to %s", (status, code, expected) => {
    expect(detailPageStateKind(new RuntimeApiError(status, { code }, code))).toBe(expected);
  });

  it("recognizes stale validation evidence even when it is not an HTTP 409", () => {
    const error = new Error("backend.change_plan.snapshot_stale");
    expect(detailPageStateKind(error)).toBe("conflict");
    expect(isDetailConflictError(error)).toBe(true);
  });
});
