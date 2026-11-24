package lnclient

import "testing"

func TestFeeLimitSats(t *testing.T) {
	cases := []struct {
		amt, want int64
	}{
		{0, 1},
		{1, 1},
		{10, 1},
		{333, 1},
		{334, 2},
		{1000, 3},
		{10000, 30},
	}
	for _, tc := range cases {
		if got := feeLimitSats(tc.amt); got != tc.want {
			t.Errorf("feeLimitSats(%d) = %d, want %d", tc.amt, got, tc.want)
		}
	}
}
