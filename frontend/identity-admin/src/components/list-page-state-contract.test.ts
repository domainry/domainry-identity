import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string) {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

const sharedTable = source("./data-table.tsx");

const dataTableListPages = [
  "../features/org/identity-accounts-page.tsx",
  "../features/org/roles.tsx",
  "../features/org/menus.tsx",
  "../features/system/metadata.tsx",
] as const;

describe("production list page state contract", () => {
  it("keeps loading, error, retry, empty, and filtered-empty behavior in the shared table", () => {
    expect(sharedTable).toContain("if (isLoading)");
    expect(sharedTable).toContain("if (error)");
    expect(sharedTable).toContain("onClick={onRetry}");
    expect(sharedTable).toContain("const hasActiveFilters");
    expect(sharedTable).toContain("hasActiveToolbarFilters");
    expect(sharedTable).toContain("dataTable.filteredEmptyTitle");
    expect(sharedTable).toContain("dataTable.filteredEmptyDescription");
    expect(sharedTable).toContain("if (!data.length && !search && !toolbarFilters)");
    expect(sharedTable).toContain("action={hasActiveFilters ? undefined : emptyAction}");
    expect(sharedTable).toContain("<DataTableToolbar");
    expect(sharedTable).toContain("data-table-refreshing");
    expect(sharedTable).toContain("isRefreshing || !table.getCanNextPage()");
  });

  it.each(dataTableListPages)("%s delegates query failure and retry to DataTable", (relativePath) => {
    const page = source(relativePath);
    expect(page).toContain("<DataTable");
    expect(page).toMatch(/(?:isLoading=|<PageQueryState|if \((?:query|[A-Za-z]+Query)\.error)/);
    expect(page).toContain("error=");
    expect(page).toContain("onRetry=");
  });

  it("covers external filters that the shared table cannot infer", () => {
    const menus = source("../features/org/menus.tsx");
    expect(menus).toContain("selectedMenuId ? t('menus.filteredEmptyTitle')");
  });

  it("keeps custom list implementations on explicit query and empty-state contracts", () => {
    const organizationUnits = source("../features/organization-units/organization-unit-management.tsx");
    expect(organizationUnits).toContain("<Skeleton");
    expect(organizationUnits).toContain("common.retry");
    expect(organizationUnits).toContain("organizationUnit.filteredEmpty.title");
  });
});
