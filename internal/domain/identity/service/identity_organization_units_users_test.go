package service

import (
	"errors"
	"reflect"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestUpsertOrganizationUnitBuildsHierarchy(t *testing.T) {
	repository := &identityOrganizationUnitUserRepository{}
	service := NewIdentityDomainService(repository, nil)
	root := identitymodel.IdentityOrganizationUnit{ID: "region", Code: "REGION", Name: "Region", NodeType: identitymodel.IdentityOrganizationUnitRegion}
	if err := service.UpsertOrganizationUnit(t.Context(), root); err != nil {
		t.Fatal(err)
	}
	parentID := " region "
	store := identitymodel.IdentityOrganizationUnit{ID: "store", Code: "STORE", Name: "Store", NodeType: identitymodel.IdentityOrganizationUnitStore, ParentID: &parentID}
	if err := service.UpsertOrganizationUnit(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	got := repository.organizationUnits[1]
	if got.Path != "/region/store" || got.Depth != 1 || !reflect.DeepEqual(got.AncestorIDs, []string{"region"}) || got.ParentID == nil || *got.ParentID != "region" {
		t.Fatalf("organization unit=%+v", got)
	}
}

func TestUpsertOrganizationUnitOwnsDerivedHierarchyFactsAndReparentsSubtree(t *testing.T) {
	repository := &identityOrganizationUnitUserRepository{}
	service := NewIdentityDomainService(repository, nil)
	for _, unit := range []identitymodel.IdentityOrganizationUnit{
		{ID: "root-a", Code: "ROOT-A", Name: "Root A", NodeType: identitymodel.IdentityOrganizationUnitRegion, Path: "/caller/path", AncestorIDs: []string{"caller"}, Depth: 99},
		{ID: "root-b", Code: "ROOT-B", Name: "Root B", NodeType: identitymodel.IdentityOrganizationUnitRegion},
	} {
		if err := service.UpsertOrganizationUnit(t.Context(), unit); err != nil {
			t.Fatal(err)
		}
	}
	rootA, rootB := "root-a", "root-b"
	for _, unit := range []identitymodel.IdentityOrganizationUnit{
		{ID: "parent", Code: "PARENT", Name: "Parent", NodeType: identitymodel.IdentityOrganizationUnitDepartment, ParentID: &rootB},
		{ID: "child", Code: "CHILD", Name: "Child", NodeType: identitymodel.IdentityOrganizationUnitTeam, ParentID: &rootA},
	} {
		if err := service.UpsertOrganizationUnit(t.Context(), unit); err != nil {
			t.Fatal(err)
		}
	}
	child := "child"
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "grandchild", Code: "GRANDCHILD", Name: "Grandchild", NodeType: identitymodel.IdentityOrganizationUnitTeam, ParentID: &child}); err != nil {
		t.Fatal(err)
	}
	parent := "parent"
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "child", Code: "CHILD", Name: "Child", NodeType: identitymodel.IdentityOrganizationUnitTeam, ParentID: &parent, Path: "/forged"}); err != nil {
		t.Fatal(err)
	}

	byID := map[string]identitymodel.IdentityOrganizationUnit{}
	for _, unit := range repository.organizationUnits {
		byID[unit.ID] = unit
	}
	if root := byID["root-a"]; root.Path != "/root-a" || root.Depth != 0 || len(root.AncestorIDs) != 0 {
		t.Fatalf("root hierarchy facts=%+v", root)
	}
	if got := byID["child"]; got.Path != "/root-b/parent/child" || got.Depth != 2 || !reflect.DeepEqual(got.AncestorIDs, []string{"root-b", "parent"}) {
		t.Fatalf("child hierarchy facts=%+v", got)
	}
	if got := byID["grandchild"]; got.Path != "/root-b/parent/child/grandchild" || got.Depth != 3 || !reflect.DeepEqual(got.AncestorIDs, []string{"root-b", "parent", "child"}) {
		t.Fatalf("grandchild hierarchy facts=%+v", got)
	}
}

func TestUpsertOrganizationUnitRollsBackWholeDerivedSubtree(t *testing.T) {
	root := identitymodel.IdentityOrganizationUnit{ID: "root", Code: "ROOT", Name: "Root", NodeType: identitymodel.IdentityOrganizationUnitRegion, Path: "/root"}
	rootID := root.ID
	child := identitymodel.IdentityOrganizationUnit{ID: "child", Code: "CHILD", Name: "Child", NodeType: identitymodel.IdentityOrganizationUnitTeam, ParentID: &rootID, Path: "/root/child", AncestorIDs: []string{"root"}, Depth: 1}
	childID := child.ID
	grandchild := identitymodel.IdentityOrganizationUnit{ID: "grandchild", Code: "GRANDCHILD", Name: "Grandchild", NodeType: identitymodel.IdentityOrganizationUnitTeam, ParentID: &childID, Path: "/root/child/grandchild", AncestorIDs: []string{"root", "child"}, Depth: 2}
	repository := &identityOrganizationUnitUserRepository{
		organizationUnits:     []identitymodel.IdentityOrganizationUnit{root, child, grandchild},
		upsertOrganizationErr: errIdentityOrganizationUnitUserEdge,
		upsertOrganizationAt:  2,
	}
	before := append([]identitymodel.IdentityOrganizationUnit(nil), repository.organizationUnits...)
	if err := NewIdentityDomainService(repository, nil).UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{
		ID: "child", Code: "CHILD", Name: "Renamed Child", NodeType: identitymodel.IdentityOrganizationUnitTeam, ParentID: &rootID,
	}); !errors.Is(err, errIdentityOrganizationUnitUserEdge) {
		t.Fatalf("error=%v", err)
	}
	if !reflect.DeepEqual(repository.organizationUnits, before) {
		t.Fatalf("partial subtree write=%+v want=%+v", repository.organizationUnits, before)
	}
}

func TestUpsertUserStoresPrimaryOrganizationAndPersonnelFields(t *testing.T) {
	repository := &identityOrganizationUnitUserRepository{organizationUnits: []identitymodel.IdentityOrganizationUnit{{ID: "team", Code: "TEAM", Name: "Team", NodeType: identitymodel.IdentityOrganizationUnitTeam, Status: identitymodel.IdentityStatusActive}}}
	service := NewIdentityDomainService(repository, nil)
	err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{
		ID: " user ", Name: " User ", Email: " USER@example.com ", OrgID: " team ",
		WorkerNo: " E001 ", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
		StartDate: "2026-01-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := repository.users[0]
	if got.ID != "user" || got.Email != "user@example.com" || got.OrgID != "team" || got.WorkerNo != "E001" || got.WorkerType != identitymodel.IdentityWorkerEmployee || got.WorkStatus != identitymodel.IdentityWorkActive {
		t.Fatalf("user=%+v", got)
	}
}

func TestUpsertUserBuildsAndReparentsReportingSubtree(t *testing.T) {
	repository := &identityOrganizationUnitUserRepository{users: []identitymodel.IdentityUser{
		{ID: "boss", Name: "Boss", Email: "boss@example.com", ReportingPath: "/boss", Status: identitymodel.IdentityStatusActive},
		{ID: "new-boss", Name: "New Boss", Email: "new-boss@example.com", ReportingPath: "/new-boss", Status: identitymodel.IdentityStatusActive},
		{ID: "employee", Name: "Employee", Email: "employee@example.com", ManagerUserID: "boss", ReportingPath: "/boss/employee", Status: identitymodel.IdentityStatusActive},
		{ID: "report", Name: "Report", Email: "report@example.com", ManagerUserID: "employee", ReportingPath: "/boss/employee/report", Status: identitymodel.IdentityStatusActive},
	}}
	service := NewIdentityDomainService(repository, nil)
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{
		ID: "employee", Name: "Employee", Email: "employee@example.com", ManagerUserID: "new-boss", Status: identitymodel.IdentityStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if got := repository.users[2]; got.ManagerUserID != "new-boss" || got.ReportingPath != "/new-boss/employee" {
		t.Fatalf("employee=%+v", got)
	}
	if got := repository.users[3]; got.ManagerUserID != "employee" || got.ReportingPath != "/new-boss/employee/report" {
		t.Fatalf("direct report=%+v", got)
	}
}

func TestUpsertUserRejectsReportingCycle(t *testing.T) {
	repository := &identityOrganizationUnitUserRepository{users: []identitymodel.IdentityUser{
		{ID: "employee", Name: "Employee", Email: "employee@example.com", ReportingPath: "/employee", Status: identitymodel.IdentityStatusActive},
		{ID: "report", Name: "Report", Email: "report@example.com", ManagerUserID: "employee", ReportingPath: "/employee/report", Status: identitymodel.IdentityStatusActive},
	}}
	service := NewIdentityDomainService(repository, nil)
	err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{
		ID: "employee", Name: "Employee", Email: "employee@example.com", ManagerUserID: "report", Status: identitymodel.IdentityStatusActive,
	})
	if code := apperror.CodeOf(err); code != "backend.identity.user_reporting_cycle" {
		t.Fatalf("error=%v code=%q", err, code)
	}
}
