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
