package revision

import (
	"reflect"
	"strings"
	"testing"
)

func TestGoReviewHandlesAliasesTimeoutsAndPhysicalLines(t *testing.T) {
	source := `package sample
import (
	web "net/http"
	"time"
	t "crypto/tls"
	"crypto/hmac"
	"crypto/sha1"
)
func review() {
	_ = web.Client{}
	_ = web.Client{Timeout: time.Second}
	_ = web.Server{ReadTimeout: time.Second, ReadHeaderTimeout: -1}
	_ = web.Server{ReadTimeout: time.Second}
	_ = t.Config{MinVersion: t.VersionTLS11, InsecureSkipVerify: (true)}
	_ = t.Config{MinVersion: t.VersionTLS13}
	_ = hmac.New(sha1.New, nil)
	{
		true := false
		_ = t.Config{InsecureSkipVerify: true}
	}
	{
		web := struct{Get func()}{}
		web.Get()
	}
//line alternate.go:900
	web.Head("https://fixture.invalid")
}
`
	report, err := ReviewGo([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	var lines []int
	for _, finding := range report.Signals {
		rules = append(rules, finding.Rule)
		lines = append(lines, finding.Line)
		if finding.Column < 1 {
			t.Fatalf("columna: %+v", finding)
		}
	}
	want := []string{"http-cliente-timeout", "http-servidor-cabeceras", "tls-version-heredada", "tls-verificacion", "hmac-hash-heredado", "http-limites"}
	if !reflect.DeepEqual(rules, want) || !reflect.DeepEqual(lines, []int{10, 12, 14, 14, 16, 26}) || report.Total != len(want) {
		t.Fatalf("reglas=%v líneas=%v total=%d", rules, lines, report.Total)
	}
}

func TestGoReviewReportsTruncatedFindings(t *testing.T) {
	source := "package sample\nimport \"net/http\"\nfunc review() {\n" + strings.Repeat("_ = http.Client{}\n", MaxFindings+2) + "}\n"
	report, err := ReviewGo([]byte(source))
	if err != nil || len(report.Signals) != MaxFindings || report.Total != MaxFindings+2 {
		t.Fatalf("visibles=%d total=%d, %v", len(report.Signals), report.Total, err)
	}
}
