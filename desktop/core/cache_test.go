package core

import (
	"bytes"
	"fmt"
	"testing"
)

// A6: LRU semantics — 64 entries max, oldest evicted first, Get refreshes.
func TestCacheLRU(t *testing.T) {
	c := NewCache()
	for i := 0; i < 70; i++ {
		c.Put(fmt.Sprintf("sha%02d", i), []byte(fmt.Sprintf("data%02d", i)))
	}
	if c.Len() != 64 {
		t.Fatalf("want 64 entries, got %d", c.Len())
	}
	if _, ok := c.Get("sha00"); ok {
		t.Error("sha00 should have been evicted (LRU)")
	}
	if b, ok := c.Get("sha69"); !ok || string(b) != "data69" {
		t.Errorf("sha69 missing: %v %q", ok, b)
	}
	// Get refreshes recency: sha06 survives the next eviction round
	if _, ok := c.Get("sha06"); !ok {
		t.Fatal("sha06 should still be cached")
	}
	for i := 70; i < 76; i++ {
		c.Put(fmt.Sprintf("sha%02d", i), []byte("x"))
	}
	if _, ok := c.Get("sha06"); !ok {
		t.Error("refreshed sha06 was evicted too early")
	}
	if _, ok := c.Get("sha07"); ok {
		t.Error("untouched sha07 should be gone")
	}
	// byte cap: one 31 MiB blob fits, a second evicts the first
	big := NewCache()
	big.Put("a", bytes.Repeat([]byte{1}, 31<<20))
	big.Put("b", bytes.Repeat([]byte{2}, 31<<20))
	if _, ok := big.Get("a"); ok {
		t.Error("byte cap eviction failed")
	}
	if _, ok := big.Get("b"); !ok {
		t.Error("b should be cached")
	}
	// Clear empties everything
	big.Clear()
	if big.Len() != 0 {
		t.Errorf("Clear left %d entries", big.Len())
	}
}
