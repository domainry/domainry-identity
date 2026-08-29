package connection

import "testing"

func TestEngineForBuildsConfiguredEngine(t *testing.T) {
	for configured, expected := range map[string]string{
		"": "sqlite", "sqlite": "sqlite", "sqlite3": "sqlite",
		"mysql": "mysql", "postgres": "postgres", "postgresql": "postgres", "pgx": "postgres",
	} {
		engine, err := EngineFor(configured)
		if err != nil {
			t.Fatalf("EngineFor(%q): %v", configured, err)
		}
		if engine.Name() != expected {
			t.Fatalf("EngineFor(%q).Name()=%q want=%q", configured, engine.Name(), expected)
		}
	}
}

func TestEngineForRejectsUnsupportedDriver(t *testing.T) {
	if _, err := EngineFor("oracle"); err == nil {
		t.Fatal("unsupported driver accepted")
	}
}
