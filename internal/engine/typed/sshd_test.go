package typed

import (
	"os"
	"strings"
	"testing"
)

func TestParseSSHD(t *testing.T) {
	b, err := os.ReadFile("testdata/sshd-T.txt")
	if err != nil {
		t.Fatal(err)
	}
	m := ParseSSHD(string(b))
	if m["permitrootlogin"] != "without-password" {
		t.Errorf("permitrootlogin = %q", m["permitrootlogin"])
	}
	if m["passwordauthentication"] != "yes" {
		t.Errorf("passwordauthentication = %q", m["passwordauthentication"])
	}
	if m["maxauthtries"] != "6" {
		t.Errorf("maxauthtries = %q", m["maxauthtries"])
	}
	if m["permitemptypasswords"] != "no" {
		t.Errorf("permitemptypasswords = %q", m["permitemptypasswords"])
	}
	if m["pubkeyauthentication"] != "yes" {
		t.Errorf("pubkeyauthentication = %q", m["pubkeyauthentication"])
	}
	if !strings.Contains(m["ciphers"], "chacha20-poly1305@openssh.com") {
		t.Errorf("ciphers = %q", m["ciphers"])
	}
}
