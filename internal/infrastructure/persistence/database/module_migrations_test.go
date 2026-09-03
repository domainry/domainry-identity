package database

import (
	"testing"

	"github.com/domainry/domainry-audit-sdk/modulehost"
)

func TestHostModuleMigrationChecksumIncludesBaselineUsingRuntimeLedgerIdentity(t *testing.T) {
	migration := modulehost.SchemaMigration{
		Version: 1,
		Name:    "audit_events",
		Statements: []string{
			"CREATE TABLE",
		},
		Baseline: &modulehost.SchemaBaseline{Tables: []modulehost.SchemaTable{{
			Name: "_audit_events",
			Columns: []modulehost.SchemaColumn{{
				Name: "id", Type: "TEXT", PrimaryKey: true,
			}},
			Indexes: []modulehost.SchemaIndex{{
				Name: "idx_audit_id", Unique: true, Columns: []string{"id"},
			}},
		}}},
	}

	const want = "5f2deb1ec971b688cb4c13211d418d31a2806cddbc0c42fece08a7281bb5fa4c"
	if got := hostModuleMigrationChecksum(migration); got != want {
		t.Fatalf("host module migration checksum=%s want=%s", got, want)
	}
	withoutBaseline := migration
	withoutBaseline.Baseline = nil
	if hostModuleMigrationChecksum(withoutBaseline) == want {
		t.Fatal("baseline was omitted from host migration checksum identity")
	}
}
