package probe

import (
	"strings"

	"github.com/Shotafry/talos/internal/catalog"
)

// Cache deduplica probes caros (sshd -T, ss, pkgmgr...) por firma de lectura,
// para que varios checks que leen lo mismo no relancen el comando.
type Cache struct{ m map[string]RawRead }

func NewCache() *Cache { return &Cache{m: map[string]RawRead{}} }

func (c *Cache) Capture(read catalog.Read, allow map[string]bool, timeoutMs int) RawRead {
	key := strings.Join([]string{
		read.Type, read.Key, read.Path, strings.Join(read.Cmd, " "), read.Unit, read.Op, read.User, read.Name,
	}, "|")
	if v, ok := c.m[key]; ok {
		return v
	}
	v := Capture(read, allow, timeoutMs)
	c.m[key] = v
	return v
}
