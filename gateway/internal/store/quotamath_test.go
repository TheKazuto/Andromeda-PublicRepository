package store

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestAllocateConsumption(t *testing.T) {
	cb := func(id string, amount, consumed int64) creditBucket {
		return creditBucket{id: id, amount: amount, consumed: consumed}
	}

	t.Run("invalid cost", func(t *testing.T) {
		if _, err := allocateConsumption(0, nil, 0, 100, 0, 0, false, false); err == nil {
			t.Fatal("want error for cost=0")
		}
		if _, err := allocateConsumption(-5, nil, 0, 100, 0, 0, false, false); err == nil {
			t.Fatal("want error for cost<0")
		}
	})

	t.Run("monthly only", func(t *testing.T) {
		got, err := allocateConsumption(30, nil, 10, 100, 0, 200, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if got.fromCredits != 0 || got.fromMonthly != 30 || got.fromOverage != 0 {
			t.Fatalf("split = %+v, want monthly=30", got)
		}
		if len(got.creditDebits) != 0 || len(got.creditUpdates) != 0 {
			t.Fatalf("unexpected credit activity: %+v", got)
		}
	})

	t.Run("credits drained before monthly, oldest first", func(t *testing.T) {
		// Two credits: c1 has 40 left, c2 has 100 left. Cost 50 → 40 from c1
		// (exhausts it), 10 from c2, 0 from monthly.
		got, err := allocateConsumption(50,
			[]creditBucket{cb("c1", 50, 10), cb("c2", 100, 0)},
			0, 100, 0, 200, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if got.fromCredits != 50 || got.fromMonthly != 0 {
			t.Fatalf("split = %+v, want credits=50 monthly=0", got)
		}
		wantDebits := []CreditDebit{{CreditID: "c1", Amount: 40}, {CreditID: "c2", Amount: 10}}
		if !reflect.DeepEqual(got.creditDebits, wantDebits) {
			t.Fatalf("creditDebits = %+v, want %+v", got.creditDebits, wantDebits)
		}
		wantUpdates := []creditUpdate{
			{id: "c1", newConsumed: 50, exhausted: true},
			{id: "c2", newConsumed: 10, exhausted: false},
		}
		if !reflect.DeepEqual(got.creditUpdates, wantUpdates) {
			t.Fatalf("creditUpdates = %+v, want %+v", got.creditUpdates, wantUpdates)
		}
	})

	t.Run("zero-availability credit rows skipped", func(t *testing.T) {
		got, err := allocateConsumption(20,
			[]creditBucket{cb("full", 30, 30), cb("ok", 50, 5)},
			0, 100, 0, 200, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if got.fromCredits != 20 {
			t.Fatalf("fromCredits = %d, want 20", got.fromCredits)
		}
		if len(got.creditDebits) != 1 || got.creditDebits[0].CreditID != "ok" {
			t.Fatalf("creditDebits = %+v, want only 'ok'", got.creditDebits)
		}
	})

	t.Run("credits + monthly + overage chained", func(t *testing.T) {
		// 10 from credits, monthly avail = 100-95 = 5, overage covers the rest.
		got, err := allocateConsumption(40,
			[]creditBucket{cb("c", 10, 0)},
			95, 100, 0, 200, true, true)
		if err != nil {
			t.Fatal(err)
		}
		if got.fromCredits != 10 || got.fromMonthly != 5 || got.fromOverage != 25 {
			t.Fatalf("split = %+v, want credits=10 monthly=5 overage=25", got)
		}
	})

	t.Run("monthly already over limit -> straight to overage", func(t *testing.T) {
		got, err := allocateConsumption(7, nil, 120, 100, 0, 200, true, true)
		if err != nil {
			t.Fatal(err)
		}
		if got.fromMonthly != 0 || got.fromOverage != 7 {
			t.Fatalf("split = %+v, want monthly=0 overage=7", got)
		}
	})

	t.Run("quota exceeded - overage disabled", func(t *testing.T) {
		_, err := allocateConsumption(50, nil, 80, 100, 0, 200, false, true)
		if !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("err = %v, want ErrQuotaExceeded", err)
		}
	})
	t.Run("quota exceeded - no card", func(t *testing.T) {
		_, err := allocateConsumption(50, nil, 80, 100, 0, 200, true, false)
		if !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("err = %v, want ErrQuotaExceeded", err)
		}
	})
	t.Run("quota exceeded - overage cap too small", func(t *testing.T) {
		// monthly avail = 0, overage avail = 200-195 = 5, need 6.
		_, err := allocateConsumption(6, nil, 100, 100, 195, 200, true, true)
		if !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("err = %v, want ErrQuotaExceeded", err)
		}
	})
	t.Run("overage cap exactly covers", func(t *testing.T) {
		got, err := allocateConsumption(5, nil, 100, 100, 195, 200, true, true)
		if err != nil {
			t.Fatal(err)
		}
		if got.fromOverage != 5 {
			t.Fatalf("fromOverage = %d, want 5", got.fromOverage)
		}
	})

	t.Run("on quota exceeded nothing is reported as taken", func(t *testing.T) {
		// Even though credits could partially cover, a hard ErrQuotaExceeded
		// means the whole charge is rejected — caller must not apply a partial.
		got, err := allocateConsumption(100,
			[]creditBucket{cb("c", 10, 0)},
			95, 100, 0, 200, false, false)
		if !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("err = %v, want ErrQuotaExceeded", err)
		}
		if got.fromCredits != 0 || len(got.creditDebits) != 0 {
			t.Fatalf("partial allocation leaked on rejection: %+v", got)
		}
	})
}

func TestCrossedThresholds(t *testing.T) {
	cases := []struct {
		name                 string
		limit, old, new      int64
		c80, c95, c100, c200 bool
	}{
		{"no limit", 0, 50, 500, false, false, false, false},
		{"crosses 80 only", 100, 79, 81, true, false, false, false},
		{"crosses 80 and 95 in one go", 100, 50, 96, true, true, false, false},
		{"crosses 100", 100, 99, 100, false, false, true, false},
		{"crosses 200 (overage cap)", 100, 199, 201, false, false, false, true},
		{"already above, no re-fire", 100, 110, 130, false, false, false, false},
		{"exactly lands on threshold", 1000, 799, 800, true, false, false, false},
		{"jumps everything", 100, 0, 250, true, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g80, g95, g100, g200 := crossedThresholds(c.limit, c.old, c.new)
			if g80 != c.c80 || g95 != c.c95 || g100 != c.c100 || g200 != c.c200 {
				t.Fatalf("got (%v,%v,%v,%v) want (%v,%v,%v,%v)", g80, g95, g100, g200, c.c80, c.c95, c.c100, c.c200)
			}
		})
	}
}

func TestRollPeriod(t *testing.T) {
	// nextPeriodEnd / annualPeriodEnd are the real step functions; verify the
	// loop catches up past `now` no matter how many windows are skipped.
	expired := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("monthly one step", func(t *testing.T) {
		now := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
		start, end := rollPeriod(expired, false, now)
		if !start.Equal(expired) {
			t.Fatalf("start = %v, want %v", start, expired)
		}
		if !now.Before(end) {
			t.Fatalf("end = %v must be after now %v", end, now)
		}
		if !end.Equal(nextPeriodEnd(expired)) {
			t.Fatalf("end = %v, want one monthly step %v", end, nextPeriodEnd(expired))
		}
	})

	t.Run("monthly dormant several periods", func(t *testing.T) {
		now := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
		start, end := rollPeriod(expired, false, now)
		if !now.Before(end) {
			t.Fatalf("end %v must be after now %v", end, now)
		}
		// start should be the window boundary immediately before `now`.
		if !start.Before(now) || !now.Before(end) {
			t.Fatalf("now %v not inside [%v, %v)", now, start, end)
		}
		// And the previous boundary must NOT also contain `now`.
		if !now.Before(end) {
			t.Fatal("end is not strictly after now")
		}
	})

	t.Run("annual step", func(t *testing.T) {
		now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		start, end := rollPeriod(expired, true, now)
		if !start.Equal(expired) {
			t.Fatalf("start = %v, want %v", start, expired)
		}
		if !end.Equal(annualPeriodEnd(expired)) {
			t.Fatalf("end = %v, want one annual step %v", end, annualPeriodEnd(expired))
		}
	})

	t.Run("annual dormant multiple years", func(t *testing.T) {
		now := time.Date(2030, 3, 1, 0, 0, 0, 0, time.UTC)
		start, end := rollPeriod(expired, true, now)
		if !start.Before(now) || !now.Before(end) {
			t.Fatalf("now %v not inside [%v, %v)", now, start, end)
		}
	})
}
