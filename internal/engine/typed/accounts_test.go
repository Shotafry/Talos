package typed

import (
	"os"
	"testing"
)

func TestShadowState(t *testing.T) {
	cases := map[string]string{
		"root:*:20627:0:99999:7:::":  "NOLOGIN",
		"user:!:20627:0:99999:7:::":  "LOCKED",
		"user::20627:0:99999:7:::":   "EMPTY",
		"user:$6$abc$def:20627:0:::": "PASSWORD",
		"user:!!:20627:0:99999:7:::": "LOCKED",
	}
	for line, want := range cases {
		if got := ShadowState(line); got != want {
			t.Errorf("ShadowState(%q)=%q want %q", line, got, want)
		}
	}
}

func TestUID0CountRealPasswd(t *testing.T) {
	b, _ := os.ReadFile("testdata/passwd.txt")
	if n := UID0Count(string(b)); n != 1 {
		t.Fatalf("UID0Count = %d, want 1 (solo root)", n)
	}
}

func TestHasEmptyPasswordRealShadow(t *testing.T) {
	b, _ := os.ReadFile("testdata/shadow.txt")
	if HasEmptyPassword(string(b)) {
		t.Fatal("la shadow real no tiene contrasenas vacias")
	}
}
