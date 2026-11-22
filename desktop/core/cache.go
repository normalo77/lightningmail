package core

import (
	"container/list"
	"sync"
)

// Cache is the RAM blob cache for the reader (Rotliste §3): LRU, max 64
// entries, max 32 MiB total, mutex-guarded. Evicted/cleared buffers are
// zeroed (they held decrypted attachment bytes).
type Cache struct {
	mu       sync.Mutex
	maxEnt   int
	maxBytes int
	bytes    int
	ll       *list.List
	items    map[string]*list.Element
}

type cacheEntry struct {
	sha  string
	data []byte
}

// NewCache returns an empty cache. cfg.CacheMB sizes the byte ceiling
// (0/absent = 32 MiB); entry count scales with it (min 64).
func NewCache(cfg *Config) *Cache {
	mb := 32
	if cfg != nil && cfg.CacheMB > 0 {
		mb = cfg.CacheMB
	}
	ent := 64
	if mb*2 > ent {
		ent = mb * 2 // ~8 MiB average slice assumption
	}
	return &Cache{maxEnt: ent, maxBytes: mb << 20, ll: list.New(), items: map[string]*list.Element{}}
}

// Get returns a blob (ok=false on miss) and marks it as recently used.
func (c *Cache) Get(sha string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[sha]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*cacheEntry).data, true
	}
	return nil, false
}

// Put stores a blob, evicting LRU entries over the limits.
func (c *Cache) Put(sha string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[sha]; ok {
		c.bytes -= len(el.Value.(*cacheEntry).data)
		clear(el.Value.(*cacheEntry).data)
		c.ll.Remove(el)
		delete(c.items, sha)
	}
	if len(data) > c.maxBytes {
		return // single blob bigger than the whole cache: don't cache it
	}
	el := c.ll.PushFront(&cacheEntry{sha: sha, data: data})
	c.items[sha] = el
	c.bytes += len(data)
	for c.ll.Len() > c.maxEnt || c.bytes > c.maxBytes {
		c.evictOldest()
	}
}

func (c *Cache) evictOldest() {
	el := c.ll.Back()
	if el == nil {
		return
	}
	e := el.Value.(*cacheEntry)
	clear(e.data) // zero decrypted bytes before dropping the reference
	c.bytes -= len(e.data)
	c.ll.Remove(el)
	delete(c.items, e.sha)
}

// Clear drops everything (mail switch / shutdown) and zeroes the buffers.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.ll.Len() > 0 {
		c.evictOldest()
	}
}

// Len is the number of cached entries (tests + log lines).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
