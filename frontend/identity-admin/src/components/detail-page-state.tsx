import type { ReactNode } from "react";
import { Alert, AlertDescription, AlertTitle, Button, Skeleton } from "@domainry/ui";
import { EmptyState } from "@/components/empty-state";
import { PageShell } from "@/components/page-shell";
import { useI18n } from "@/lib/i18n";
import { runtimeApiError } from "@/lib/runtime-api";

export type DetailPageStateKind =
  | "loading"
  | "not-found"
  | "permission-denied"
  | "conflict"
  | "error";

const conflictFragments = [
  "conflict",
  "stale",
  "version_mismatch",
  "hash_mismatch",
  "revision_mismatch",
] as const;

export function detailPageStateKind(error?: unknown): Exclude<DetailPageStateKind, "loading"> {
  const runtimeError = runtimeApiError(error);
  if (runtimeError?.status === 404) return "not-found";
  if (runtimeError?.status === 401 || runtimeError?.status === 403) return "permission-denied";
  if (runtimeError?.status === 409 || runtimeError?.status === 412) return "conflict";
  const evidence = `${runtimeError?.code ?? ""} ${error instanceof Error ? error.message : ""}`.toLowerCase();
  return conflictFragments.some((fragment) => evidence.includes(fragment)) ? "conflict" : "error";
}

export function isDetailConflictError(error: unknown) {
  return detailPageStateKind(error) === "conflict";
}

export function DetailPageState({
  title,
  description,
  kind,
  error,
  onRetry,
  onBack,
  backLabel,
}: {
  title: ReactNode;
  description?: ReactNode;
  kind?: DetailPageStateKind;
  error?: unknown;
  onRetry?: () => void;
  onBack?: () => void;
  backLabel?: ReactNode;
}) {
  const { t } = useI18n();
  const resolvedKind = kind ?? (error ? detailPageStateKind(error) : "loading");
  const errorMessage = error instanceof Error ? error.message : "";

  return (
    <PageShell title={title} description={description}>
      {resolvedKind === "loading" ? (
        <Skeleton className="h-72 w-full rounded-lg" />
      ) : resolvedKind === "not-found" ? (
        <EmptyState
          title={t("detailState.notFoundTitle")}
          description={t("detailState.notFoundDescription")}
          action={onBack ? <Button variant="outline" onClick={onBack}>{backLabel ?? t("detailState.back")}</Button> : undefined}
        />
      ) : (
        <Alert variant="destructive">
          <AlertTitle>
            {resolvedKind === "permission-denied"
              ? t("detailState.permissionDeniedTitle")
              : resolvedKind === "conflict"
                ? t("detailState.conflictTitle")
                : t("detailState.errorTitle")}
          </AlertTitle>
          <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
            <span>
              {resolvedKind === "permission-denied"
                ? t("detailState.permissionDeniedDescription")
                : resolvedKind === "conflict"
                  ? t("detailState.conflictDescription")
                  : errorMessage || t("detailState.errorDescription")}
            </span>
            <div className="flex flex-wrap gap-2">
              {onBack ? <Button size="sm" variant="outline" onClick={onBack}>{backLabel ?? t("detailState.back")}</Button> : null}
              {onRetry ? <Button size="sm" variant="outline" onClick={onRetry}>{resolvedKind === "conflict" ? t("detailState.reload") : t("common.retry")}</Button> : null}
            </div>
          </AlertDescription>
        </Alert>
      )}
    </PageShell>
  );
}

export function DetailConflictAlert({
  error,
  onReload,
}: {
  error: unknown;
  onReload: () => void;
}) {
  const { t } = useI18n();
  if (!isDetailConflictError(error)) return null;
  return (
    <Alert variant="destructive" role="alert">
      <AlertTitle>{t("detailState.conflictTitle")}</AlertTitle>
      <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
        <span>{t("detailState.conflictDescription")}</span>
        <Button size="sm" variant="outline" onClick={onReload}>{t("detailState.reload")}</Button>
      </AlertDescription>
    </Alert>
  );
}
