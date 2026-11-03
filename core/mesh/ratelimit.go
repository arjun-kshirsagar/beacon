package mesh

import "time"

// bucket is a token bucket: rate tokens a second, up to burst.
type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) allow(now time.Time, rate, burst float64) bool {
	if b.last.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// limiter keeps a bucket per key, forgetting all of them if the map fills, so
// a peer inventing keys cannot grow it without bound.
type limiter[K comparable] struct {
	rate, burst float64
	max         int
	buckets     map[K]*bucket
}

func newLimiter[K comparable](rate, burst float64, max int) *limiter[K] {
	return &limiter[K]{rate: rate, burst: burst, max: max, buckets: make(map[K]*bucket)}
}

func (l *limiter[K]) allow(k K, now time.Time) bool {
	b := l.buckets[k]
	if b == nil {
		if len(l.buckets) >= l.max {
			clear(l.buckets)
		}
		b = &bucket{}
		l.buckets[k] = b
	}
	return b.allow(now, l.rate, l.burst)
}
