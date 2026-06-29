package typed

import (
	"os"
	"testing"
)

func TestParseSSNoProc(t *testing.T) {
	b, _ := os.ReadFile("testdata/ss-tlnup-noproc.txt")
	socks := ParseSS(string(b))
	var found22, found61209 bool
	for _, s := range socks {
		if s.Proto == "tcp" && s.Port == 22 && s.Addr == "0.0.0.0" {
			if !s.Wildcard {
				t.Error("0.0.0.0:22 deberia ser wildcard")
			}
			found22 = true
		}
		if s.Port == 61209 && s.Addr == "127.0.0.1" {
			if s.Wildcard {
				t.Error("127.0.0.1:61209 NO es wildcard")
			}
			found61209 = true
		}
	}
	if !found22 || !found61209 {
		t.Fatalf("no parseo bien (sin proceso): %+v", socks)
	}
}

func TestParseSSWithProcess(t *testing.T) {
	b, _ := os.ReadFile("testdata/ss-tlnup-root.txt")
	socks := ParseSS(string(b))
	var got bool
	for _, s := range socks {
		if s.Port == 22 && s.Process == "sshd" {
			got = true
		}
	}
	if !got {
		t.Fatalf("no extrajo proceso sshd: %+v", socks)
	}
}

func TestParseSSIPv6Wildcard(t *testing.T) {
	b, _ := os.ReadFile("testdata/ss-tlnup-root.txt")
	socks := ParseSS(string(b))
	var v6 bool
	for _, s := range socks {
		if s.Addr == "[::]" && s.Wildcard {
			v6 = true
		}
	}
	if !v6 {
		t.Fatalf("no detecto wildcard IPv6 [::]: %+v", socks)
	}
}
