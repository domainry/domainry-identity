package migration

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestLockManagerClosesActiveConnection(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	connection, err := database.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	manager := &LockManager{activeConnection: connection}
	if err := manager.Close(); err != nil || manager.Connection() != nil {
		t.Fatalf("close=%v connection=%v", err, manager.Connection())
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("second close=%v", err)
	}
}
