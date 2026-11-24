package core

import (
	"reflect"
	"testing"
)

func TestParseRecipients(t *testing.T) {
	cases := []struct{ in string; want []string }{
		{" a@x , b@x ;c@x ,, A@X ", []string{"a@x", "b@x", "c@x"}}, // trim + case-insensitive dedupe, first-seen order
		{"  , ; ", []string{}},
		{"bob@relay", []string{"bob@relay"}},
		{"", []string{}},
	}
	for _, tc := range cases {
		got := ParseRecipients(tc.in)
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("ParseRecipients(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestUniqueRecipients(t *testing.T) {
	got := UniqueRecipients("a@x, b@x", "B@x ; c@x")
	want := []string{"a@x", "b@x", "c@x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UniqueRecipients = %v, want %v", got, want)
	}
	if got := UniqueRecipients("", "c@x"); !reflect.DeepEqual(got, []string{"c@x"}) {
		t.Fatalf("cc-only merge = %v", got)
	}
}

func TestReplyAll(t *testing.T) {
	cases := []struct {
		name                     string
		sender, to, cc, self     string
		wantTo, wantCc           []string
	}{
		{"basic", "alice@x", "bob@x, carol@x", "dave@x", "bob@x", []string{"alice@x"}, []string{"carol@x", "dave@x"}},
		{"self as bare name", "alice@x", "bob@x, carol@x", "", "bob", []string{"alice@x"}, []string{"carol@x"}},
		{"sender duplicated in cc", "alice@x", "bob@x", "alice@x, carol@x", "bob@x", []string{"alice@x"}, []string{"carol@x"}},
		{"reply to self only", "bob@x", "bob@x", "", "bob@x", nil, nil},
		{"no headers", "alice@x", "", "", "bob@x", []string{"alice@x"}, nil},
	}
	for _, tc := range cases {
		to, cc := ReplyAll(tc.sender, tc.to, tc.cc, tc.self)
		if !reflect.DeepEqual(to, tc.wantTo) || !reflect.DeepEqual(cc, tc.wantCc) {
			t.Fatalf("%s: ReplyAll = (%v, %v), want (%v, %v)", tc.name, to, cc, tc.wantTo, tc.wantCc)
		}
	}
}

func TestHeaderCI(t *testing.T) {
	h := map[string]string{"to": "lower@x", "Cc": "canon@x"}
	if got := HeaderCI(h, "To"); got != "lower@x" {
		t.Fatalf("lowercase lookup = %q", got)
	}
	if got := HeaderCI(h, "cc"); got != "canon@x" {
		t.Fatalf("canonical lookup = %q", got)
	}
	if got := HeaderCI(h, "From"); got != "" {
		t.Fatalf("missing key = %q, want empty", got)
	}
}
