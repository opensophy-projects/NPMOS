// NginxionS: the log query of a tuning event quotes its values (CodeQL go/sql-injection)
package pg

import (
	"strings"
	"testing"

	"openappsec.io/smartsync-tuning/models"
)

func TestSQLLiteral(t *testing.T) {
	for in, want := range map[string]string{
		"plain":            "'plain'",
		"it's":             "'it''s'",
		"' or '1'='1":      "''' or ''1''=''1'",
		"a\x00b":           "'ab'",
		`back\slash'`:      `'back\slash'''`,
		"'; drop table x;": "'''; drop table x;'",
	} {
		if got := sqlLiteral(in); got != want {
			t.Errorf("sqlLiteral(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestGenerateLogQueryQuotesTheTitle(t *testing.T) {
	qg := &QueriesGen{}
	q := qg.GenerateLogQuery(models.TuneEvent{
		Severity:   "high",
		EventType:  models.EventTypeURL,
		EventTitle: "/x' or '1'='1",
	}, "asset' --")
	for _, part := range []string{"'asset'' --'", "'/x'' or ''1''=''1'"} {
		if !strings.Contains(q, part) {
			t.Errorf("the query does not quote %s: %s", part, q)
		}
	}
	if strings.Count(q, "'")%2 != 0 {
		t.Errorf("unbalanced quotes: %s", q)
	}
}

// NginxionS: a partition is named by the day it holds, under its own prefix, and is created once by several writers
func TestCreateTablePartition(t *testing.T) {
	qg := &QueriesGen{}
	stmt, err := qg.CreateTablePartition("", "2026-09-16T00:00:05.875")
	if err != nil {
		t.Fatal(err)
	}
	want := "CREATE TABLE IF NOT EXISTS appsec_p_2026_09_16 PARTITION OF appsec FOR VALUES FROM ('2026-09-16') TO ('2026-09-17')"
	if stmt != want {
		t.Fatalf("got %q, want %q", stmt, want)
	}
	if stmt, _ = qg.CreateTablePartition("", "2026-12-31T23:59:59.999"); !strings.Contains(stmt, "FROM ('2026-12-31') TO ('2027-01-01')") {
		t.Fatalf("end of the year: %q", stmt)
	}
}
