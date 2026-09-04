import { afterEach, describe, expect, it, vi } from "vitest";
import { identityAccountsApi } from "./api";
import { RuntimeApiError } from "@/lib/runtime-api";

const user = {
  id: "user-1",
  name: "Original User",
  account_type: "human",
  org_id: "support-team",
  support_org_id: "sales",
  email: "user@example.com",
  status: "active",
  version: 1,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

afterEach(() => vi.unstubAllGlobals());

describe("identity user direct authoring contract", () => {
  it("observes the backend hash and sends all required authoring headers", async () => {
    const updated = { ...user, name: "Updated User", version: 2 };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(user), {
        status: 200,
        headers: { "content-type": "application/json", "X-Resource-Hash": "user-resource-v1" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ resource: updated }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(identityAccountsApi.update(user.id, { name: updated.name, expectedResourceHash: "detail-resource-v1" })).resolves.toMatchObject({
      id: user.id,
      name: updated.name,
      version: 2,
    });

    const headers = new Headers(fetchMock.mock.calls[1]?.[1]?.headers);
    expect(headers.get("Expected-Schema-Hash")).toBe("detail-resource-v1");
    expect(headers.get("Builder-Task-ID")).toMatch(/^identity-management\.user\.web_/);
    expect(headers.get("Idempotency-Key")).toMatch(/^web_/);
    const body = JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body)) as Record<string, unknown>;
    expect(body.org_id).toBe("support-team");
    expect(body.support_org_id).toBe("sales");
  });

  it("preserves the typed backend conflict for the detail page", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(user), {
        status: 200,
        headers: { "content-type": "application/json", "X-Resource-Hash": "user-resource-v1" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        code: "backend.authoring.resource_hash_conflict",
        message: "resource changed",
      }), {
        status: 409,
        headers: { "content-type": "application/json" },
      }));
    vi.stubGlobal("fetch", fetchMock);

    const rejected = identityAccountsApi.update(user.id, { name: "Concurrent Edit" });
    await expect(rejected).rejects.toBeInstanceOf(RuntimeApiError);
    await expect(rejected).rejects.toMatchObject({
      status: 409,
      code: "backend.authoring.resource_hash_conflict",
    });
  });
});
