// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const directURL = "postgresql://neondb_owner:fixture-secret@ep-cool-darkness-123456.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"

func TestTheHelloUsesTheRuntimeRoleOnceTheStoreExists(t *testing.T) {
	values := minimal(OfficialHosted)
	values[EnvNeonHello] = "enabled"
	values[EnvDatabaseURL] = runtimeURL
	config, err := Load(environment(values))
	if err != nil || !config.HelloFromDatabase || config.NeonHello != nil || config.Database == nil {
		t.Fatalf("hello through the runtime role: %+v %v", config, err)
	}
	// Without a runtime database the Hello keeps its own Neon credential.
	delete(values, EnvDatabaseURL)
	values[EnvNeonDatabaseURL] = neonURL
	if config, err = Load(environment(values)); err != nil || !config.HelloFromDatabase || config.NeonHello == nil {
		t.Fatalf("hello through NEON_DATABASE_URL: %v", err)
	}
	values[EnvNeonHello] = "disabled"
	if config, err = Load(environment(values)); err != nil || config.HelloFromDatabase || config.NeonHello != nil {
		t.Fatalf("stateless hello: %v", err)
	}
}

func migrationValues() map[string]string {
	return map[string]string{EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: directURL}
}

func TestTheMigrationConfiguration(t *testing.T) {
	config, err := LoadMigration(environment(migrationValues()))
	if err != nil {
		t.Fatal(err)
	}
	if config.Database != "neondb" || config.RuntimeRole != DefaultRuntimeRole || config.LockTimeout != 2*time.Minute ||
		!strings.Contains(config.URL, "sslmode=verify-full") || !strings.Contains(config.URL, "/neondb?") {
		t.Fatalf("%+v", config)
	}
	values := migrationValues()
	values[EnvDatabaseName] = "arcforges_acceptance"
	values[EnvRuntimeRole] = "arcforges_acceptance_runtime"
	values[EnvRuntimeSecretFile] = "/tmp/runtime/secret.json"
	values[EnvMigrationLockTimeout] = "30s"
	config, err = LoadMigration(environment(values))
	if err != nil || config.Database != "arcforges_acceptance" || !strings.Contains(config.URL, "/arcforges_acceptance?") ||
		!strings.Contains(config.Maintenance, "/neondb?") || config.RuntimeRole != "arcforges_acceptance_runtime" || config.LockTimeout != 30*time.Second {
		t.Fatalf("acceptance: %+v %v", config, err)
	}
	local := map[string]string{EnvMode: string(SelfHosted), EnvMigrationDatabaseURL: "postgres://owner:secret@127.0.0.1:5432/center?sslmode=disable"}
	if _, err = LoadMigration(environment(local)); err != nil {
		t.Fatalf("self-hosted loopback: %v", err)
	}
}

func TestTheMigrationConfigurationRefusesWithoutEchoing(t *testing.T) {
	cases := map[string]map[string]string{
		"no mode":         {EnvMigrationDatabaseURL: directURL},
		"no url":          {EnvMode: string(OfficialHosted)},
		"pooler":          {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: strings.Replace(directURL, "123456.", "123456-pooler.", 1)},
		"plaintext":       {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: "postgres://owner:fixture-secret@127.0.0.1/center?sslmode=disable"},
		"remote plain":    {EnvMode: string(SelfHosted), EnvMigrationDatabaseURL: "postgres://owner:fixture-secret@db.example.org/center?sslmode=disable"},
		"no binding":      {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: strings.Replace(directURL, "&channel_binding=require", "", 1)},
		"no user":         {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: strings.Replace(directURL, "neondb_owner:fixture-secret@", "", 1)},
		"bad database":    {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: directURL, EnvDatabaseName: "Prod"},
		"template":        {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: directURL, EnvDatabaseName: "template1"},
		"runtime = owner": {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: directURL, EnvRuntimeRole: "neondb_owner"},
		"relative file":   {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: directURL, EnvRuntimeSecretFile: "secret.json"},
		"pooled host":     {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: directURL, EnvRuntimePooledHost: "a b"},
		"lock timeout":    {EnvMode: string(OfficialHosted), EnvMigrationDatabaseURL: directURL, EnvMigrationLockTimeout: "2h"},
	}
	for name, values := range cases {
		_, err := LoadMigration(environment(values))
		if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "fixture-secret") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestThePlanConfiguration(t *testing.T) {
	values := minimal(OfficialHosted)
	if config, err := Load(environment(values)); err != nil || config.Plan != PlanNone {
		t.Fatalf("none: %v", err)
	}
	values[EnvPlanConfiguration] = "development-fixtures"
	if config, err := Load(environment(values)); err != nil || config.Plan != PlanDevelopmentFixtures {
		t.Fatalf("fixtures: %v", err)
	}
	values[EnvPlanConfiguration] = "production"
	if _, err := Load(environment(values)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown plan configuration: %v", err)
	}
	selfHosted := minimal(SelfHosted)
	selfHosted[EnvPlanConfiguration] = "development-fixtures"
	if _, err := Load(environment(selfHosted)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("fixtures in self-hosted mode: %v", err)
	}
}
