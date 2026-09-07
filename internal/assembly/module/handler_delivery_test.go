package moduleassembly

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	organizationunit "github.com/domainry/domainry-identity/organizationunit"
	ormsqlite "github.com/domainry/domainry-orm/sqlite"
	_ "modernc.org/sqlite"
)

func TestHandlerDeliveryModuleExposesOnlyTransactionBoundNarrowCapability(t *testing.T) {
	binding := &moduleBinding{}
	if _, exposed := any(binding).(identitysdk.HandlerDeliveryBinding); exposed {
		t.Fatal("embedded module exposed an unbound HandlerDelivery")
	}
	binder := binding.HandlerDeliveryUnitOfWorkBinder()
	if _, err := binder.BindHandlerDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{Executor: &sql.DB{}}); err == nil {
		t.Fatal("plain database handle was accepted as a transaction")
	} else {
		var sdkErr *identitysdk.Error
		if !errors.As(err, &sdkErr) || sdkErr.Code != "identity.handler_delivery_transaction_required" {
			t.Fatalf("plain database transaction error=%v", err)
		}
	}
	capability, err := binder.BindHandlerDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{Executor: &sql.Tx{}})
	if err != nil || capability == nil {
		t.Fatalf("bound capability=%v err=%v", capability, err)
	}
	if _, leaked := any(capability).(identitysdk.HandlerDeliveryUnitOfWorkBinder); leaked {
		t.Fatal("project capability leaked the transaction binder")
	}
}

func TestStoreOrganizationModuleExposesOnlyTransactionBoundNarrowCapability(t *testing.T) {
	binding := &moduleBinding{}
	if _, exposed := any(binding).(identitysdk.StoreOrganizationDeliveryBinding); exposed {
		t.Fatal("embedded module exposed an unbound StoreOrganizationDelivery")
	}
	binder := binding.StoreOrganizationDeliveryUnitOfWorkBinder()
	if _, err := binder.BindStoreOrganizationDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{Executor: &sql.DB{}}); err == nil {
		t.Fatal("plain database handle was accepted as a transaction")
	}
	capability, err := binder.BindStoreOrganizationDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{Executor: &sql.Tx{}})
	if err != nil || capability == nil {
		t.Fatalf("bound capability=%v err=%v", capability, err)
	}
	if _, leaked := any(capability).(identitysdk.StoreOrganizationDeliveryUnitOfWorkBinder); leaked {
		t.Fatal("project capability leaked the StoreOrganization transaction binder")
	}
}

func TestOrganizationUnitModuleExposesOnlyTransactionBoundNarrowCapability(t *testing.T) {
	binding := &moduleBinding{}
	if _, exposed := any(binding).(organizationunit.Binding); exposed {
		t.Fatal("embedded module exposed an unbound OrganizationUnitDelivery")
	}
	binder := binding.OrganizationUnitDeliveryUnitOfWorkBinder()
	if _, err := binder.BindOrganizationUnitDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{Executor: &sql.DB{}}); err == nil {
		t.Fatal("plain database handle was accepted as a transaction")
	} else {
		var sdkErr *identitysdk.Error
		if !errors.As(err, &sdkErr) || sdkErr.Code != "identity.organization_unit_delivery_transaction_required" {
			t.Fatalf("plain database transaction error=%v", err)
		}
	}
	capability, err := binder.BindOrganizationUnitDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{Executor: &sql.Tx{}})
	if err != nil || capability == nil {
		t.Fatalf("bound capability=%v err=%v", capability, err)
	}
	if _, leaked := any(capability).(organizationunit.UnitOfWorkBinder); leaked {
		t.Fatal("project capability leaked the OrganizationUnit transaction binder")
	}
}

func TestWorkspaceIdentityUsageModuleRequiresAuthorityAndTransactionBoundCapability(t *testing.T) {
	binding := &moduleBinding{}
	if _, exposed := any(binding).(identitysdk.WorkspaceIdentityUsageAggregate); exposed {
		t.Fatal("embedded module exposed an unbound Workspace identity usage aggregate")
	}
	binder := binding.WorkspaceIdentityUsageUnitOfWorkBinder()
	if _, err := binder.BindWorkspaceIdentityUsageUnitOfWork(identitysdk.EmbeddedTransaction{Executor: &sql.DB{}}); err == nil {
		t.Fatal("plain database handle was accepted as a Workspace usage transaction")
	}
	if _, err := binder.BindWorkspaceIdentityUsageUnitOfWork(identitysdk.EmbeddedTransaction{Executor: &sql.Tx{}}); err == nil {
		t.Fatal("Workspace usage binder accepted a missing installation authority")
	} else {
		var sdkErr *identitysdk.Error
		if !errors.As(err, &sdkErr) || sdkErr.Code != "identity.workspace_usage_authority_required" {
			t.Fatalf("missing authority error=%v", err)
		}
	}
	binding.workspaceUsage = identityapplication.NewIdentityWorkspaceUsageApplicationService(identityapplication.IdentityWorkspaceUsageDependencies{})
	capability, err := binder.BindWorkspaceIdentityUsageUnitOfWork(identitysdk.EmbeddedTransaction{Executor: &sql.Tx{}})
	if err != nil || capability == nil {
		t.Fatalf("bound Workspace usage capability=%v err=%v", capability, err)
	}
	if _, leaked := any(capability).(identitysdk.WorkspaceIdentityUsageUnitOfWorkBinder); leaked {
		t.Fatal("project capability leaked the Workspace usage transaction binder")
	}
}

func TestDeliveryBindersAcceptDomainryORMSQLiteImmediateTransaction(t *testing.T) {
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "embedded-delivery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	transaction, err := ormsqlite.NewProfile().BeginWrite(t.Context(), database)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(t.Context())

	binding := &moduleBinding{}
	carrier := identitysdk.EmbeddedTransaction{Executor: transaction}
	if capability, err := binding.HandlerDeliveryUnitOfWorkBinder().BindHandlerDeliveryUnitOfWork(carrier); err != nil || capability == nil {
		t.Fatalf("bind HandlerDelivery to SQLite immediate transaction: capability=%v err=%v", capability, err)
	}
	if capability, err := binding.StoreOrganizationDeliveryUnitOfWorkBinder().BindStoreOrganizationDeliveryUnitOfWork(carrier); err != nil || capability == nil {
		t.Fatalf("bind StoreOrganizationDelivery to SQLite immediate transaction: capability=%v err=%v", capability, err)
	}
	if capability, err := binding.OrganizationUnitDeliveryUnitOfWorkBinder().BindOrganizationUnitDeliveryUnitOfWork(carrier); err != nil || capability == nil {
		t.Fatalf("bind OrganizationUnitDelivery to SQLite immediate transaction: capability=%v err=%v", capability, err)
	}
	binding.workspaceUsage = identityapplication.NewIdentityWorkspaceUsageApplicationService(identityapplication.IdentityWorkspaceUsageDependencies{})
	if capability, err := binding.WorkspaceIdentityUsageUnitOfWorkBinder().BindWorkspaceIdentityUsageUnitOfWork(carrier); err != nil || capability == nil {
		t.Fatalf("bind WorkspaceIdentityUsage to SQLite immediate transaction: capability=%v err=%v", capability, err)
	}
}
