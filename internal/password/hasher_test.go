package password

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var fastParams = Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

func newTestHasher(t testing.TB, params Params, concurrency int) *Hasher {
	t.Helper()
	h, err := NewHasher(WithParams(params), WithConcurrency(concurrency))
	if err != nil {
		t.Fatalf("NewHasher failed: %v", err)
	}
	return h
}

func TestDefaultParamsMatchOWASPMinimum(t *testing.T) {
	p := DefaultParams()
	if p.Memory != 19456 || p.Iterations != 2 || p.Parallelism != 1 || p.SaltLength != 16 || p.KeyLength != 32 {
		t.Fatalf("unexpected defaults: %+v", p)
	}
	h, err := NewHasher()
	if err != nil {
		t.Fatalf("NewHasher failed: %v", err)
	}
	if h.Params() != p || cap(h.sem) < 1 {
		t.Fatalf("unexpected hasher: params=%+v capacity=%d", h.Params(), cap(h.sem))
	}
}

func TestHashFormatWithDefaultParams(t *testing.T) {
	h, err := NewHasher()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := h.Hash(t.Context(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=19456,t=2,p=1" {
		t.Fatalf("unexpected PHC string %q", encoded)
	}
	if len(parts[4]) != 22 || len(parts[5]) != 43 {
		t.Fatalf("salt and key must be 16 and 32 bytes of unpadded base64, got %d and %d characters", len(parts[4]), len(parts[5]))
	}
	ok, needsRehash, err := h.Verify(t.Context(), "correct horse battery staple", encoded)
	if err != nil || !ok || needsRehash {
		t.Fatalf("Verify = %v %v %v", ok, needsRehash, err)
	}
}

func TestVerifyReferenceVectors(t *testing.T) {
	vectors := []struct {
		password string
		encoded  string
	}{
		{"correct horse battery staple", "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0"},
		{"пароль-с-юникодом-123", "$argon2id$v=19$m=19456,t=2,p=1$ZmVkY2JhOTg3NjU0MzIxMA$4gk6ZSo9clld9/xDwLsRtFbMVif+fBnVaIySdvC2xMA"},
		{"short-params-password", "$argon2id$v=19$m=64,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$daAoTfkIl8+qEluEDo2fBoFDUazt7/FB9noi3CGwjek"},
	}
	h, err := NewHasher()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.password, func(t *testing.T) {
			ok, _, err := h.Verify(t.Context(), v.password, v.encoded)
			if err != nil || !ok {
				t.Fatalf("reference hash was not accepted: ok=%v err=%v", ok, err)
			}
			ok, _, err = h.Verify(t.Context(), v.password+"x", v.encoded)
			if err != nil || ok {
				t.Fatalf("a different password was accepted: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestHashMatchesReferenceImplementationForTheSameSalt(t *testing.T) {
	h := newTestHasher(t, DefaultParams(), 1)
	key, err := h.derive(t.Context(), []byte("correct horse battery staple"), []byte("0123456789abcdef"), h.params)
	if err != nil {
		t.Fatal(err)
	}
	want := "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0"
	if got := encode(h.params, []byte("0123456789abcdef"), key); got != want {
		t.Fatalf("encoding differs from the reference implementation:\n got %s\nwant %s", got, want)
	}
}

func TestHashUsesFreshSalt(t *testing.T) {
	h := newTestHasher(t, fastParams, 2)
	first, err := h.Hash(t.Context(), "same password value")
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.Hash(t.Context(), "same password value")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two hashes of the same password must differ")
	}
}

func TestVerifyRoundTrip(t *testing.T) {
	h := newTestHasher(t, fastParams, 2)
	encoded, err := h.Hash(t.Context(), "S3cret passphrase, long enough")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		password string
		want     bool
	}{
		{"same", "S3cret passphrase, long enough", true},
		{"different case", "s3cret passphrase, long enough", false},
		{"prefix", "S3cret passphrase", false},
		{"empty", "", false},
		{"trailing space", "S3cret passphrase, long enough ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, needsRehash, err := h.Verify(t.Context(), tc.password, encoded)
			if err != nil || ok != tc.want || needsRehash {
				t.Fatalf("Verify = ok:%v rehash:%v err:%v, want ok:%v", ok, needsRehash, err, tc.want)
			}
		})
	}
}

func TestPasswordsAreNormalizedWithNFKC(t *testing.T) {
	h := newTestHasher(t, fastParams, 1)
	encoded, err := h.Hash(t.Context(), "ｐａｓｓｗｏｒｄ１２３４５６")
	if err != nil {
		t.Fatal(err)
	}
	for _, equivalent := range []string{"password123456", "ｐａｓｓｗｏｒｄ１２３４５６"} {
		ok, _, err := h.Verify(t.Context(), equivalent, encoded)
		if err != nil || !ok {
			t.Fatalf("%q must match its NFKC equivalent: ok=%v err=%v", equivalent, ok, err)
		}
	}
}

func TestVerifyReportsOutdatedParameters(t *testing.T) {
	old := newTestHasher(t, fastParams, 1)
	encoded, err := old.Hash(t.Context(), "old password value")
	if err != nil {
		t.Fatal(err)
	}
	stronger := fastParams
	stronger.Iterations = 2
	current := newTestHasher(t, stronger, 1)
	ok, needsRehash, err := current.Verify(t.Context(), "old password value", encoded)
	if err != nil || !ok || !needsRehash {
		t.Fatalf("Verify = ok:%v rehash:%v err:%v, want a match that needs a rehash", ok, needsRehash, err)
	}
	longerKey := fastParams
	longerKey.KeyLength = 48
	if ok, needsRehash, err = newTestHasher(t, longerKey, 1).Verify(t.Context(), "old password value", encoded); err != nil || !ok || !needsRehash {
		t.Fatalf("a different key length must need a rehash: ok:%v rehash:%v err:%v", ok, needsRehash, err)
	}
	if ok, needsRehash, err = current.Verify(t.Context(), "wrong password value", encoded); err != nil || ok || needsRehash {
		t.Fatalf("a wrong password must neither match nor ask for a rehash: ok:%v rehash:%v err:%v", ok, needsRehash, err)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	h := newTestHasher(t, fastParams, 1)
	valid, err := h.Hash(t.Context(), "valid password value")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid, "$")
	replace := func(index int, value string) string {
		changed := append([]string(nil), parts...)
		changed[index] = value
		return strings.Join(changed, "$")
	}
	cases := map[string]string{
		"empty":                  "",
		"plain text":             "not a hash",
		"bcrypt":                 "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"argon2i":                replace(1, "argon2i"),
		"argon2d":                replace(1, "argon2d"),
		"old version":            replace(2, "v=16"),
		"missing version":        replace(2, ""),
		"too few parts":          strings.Join(parts[:5], "$"),
		"too many parts":         valid + "$extra",
		"no leading dollar":      strings.TrimPrefix(valid, "$"),
		"missing memory":         replace(3, "t=1,p=1"),
		"swapped fields":         replace(3, "t=1,m=64,p=1"),
		"extra field":            replace(3, "m=64,t=1,p=1,x=1"),
		"non numeric memory":     replace(3, "m=abc,t=1,p=1"),
		"negative iterations":    replace(3, "m=64,t=-1,p=1"),
		"zero iterations":        replace(3, "m=64,t=0,p=1"),
		"zero parallelism":       replace(3, "m=64,t=1,p=0"),
		"parallelism overflow":   replace(3, "m=64,t=1,p=256"),
		"memory below minimum":   replace(3, "m=4,t=1,p=1"),
		"memory above limit":     replace(3, "m=4294967295,t=1,p=1"),
		"iterations above limit": replace(3, "m=64,t=1000000,p=1"),
		"salt not base64":        replace(4, "!!!!"),
		"salt padded":            replace(4, parts[4]+"=="),
		"salt too short":         replace(4, "YWJj"),
		"salt empty":             replace(4, ""),
		"key not base64":         replace(5, "!!!!"),
		"key too short":          replace(5, "YWJj"),
		"key empty":              replace(5, ""),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			ok, needsRehash, err := h.Verify(t.Context(), "valid password value", encoded)
			if !errors.Is(err, ErrInvalidHash) || ok || needsRehash {
				t.Fatalf("Verify = ok:%v rehash:%v err:%v, want ErrInvalidHash", ok, needsRehash, err)
			}
		})
	}
}

func TestOversizedPasswords(t *testing.T) {
	h := newTestHasher(t, fastParams, 1)
	huge := strings.Repeat("a", maxInputBytes+1)
	if _, err := h.Hash(t.Context(), huge); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Hash of an oversized password = %v, want ErrTooLong", err)
	}
	expanding := strings.Repeat("ﷺ", maxInputBytes/3)
	if _, err := h.Hash(t.Context(), expanding); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Hash of a password that grows past the limit under NFKC = %v, want ErrTooLong", err)
	}
	valid, err := h.Hash(t.Context(), "valid password value")
	if err != nil {
		t.Fatal(err)
	}
	ok, needsRehash, err := h.Verify(t.Context(), huge, valid)
	if err != nil || ok || needsRehash {
		t.Fatalf("an oversized password must simply not match: ok:%v rehash:%v err:%v", ok, needsRehash, err)
	}
	if err = h.DummyVerify(t.Context(), huge); err != nil {
		t.Fatalf("DummyVerify of an oversized password failed: %v", err)
	}
}

func TestNewHasherValidatesConfiguration(t *testing.T) {
	bad := map[string]Params{
		"zero parallelism": {Memory: 64, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32},
		"low memory":       {Memory: 7, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		"memory per lane":  {Memory: 15, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 32},
		"huge memory":      {Memory: maxMemory + 1, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		"no iterations":    {Memory: 64, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		"short salt":       {Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 4, KeyLength: 32},
		"long salt":        {Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 65, KeyLength: 32},
		"short key":        {Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 8},
		"long key":         {Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 129},
	}
	for name, params := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHasher(WithParams(params)); !errors.Is(err, ErrParams) {
				t.Fatalf("NewHasher(%+v) = %v, want ErrParams", params, err)
			}
		})
	}
	if _, err := NewHasher(WithConcurrency(0)); !errors.Is(err, ErrParams) {
		t.Fatalf("zero concurrency must be rejected, got %v", err)
	}
}

func TestConcurrencyLimitAndContext(t *testing.T) {
	h := newTestHasher(t, fastParams, 2)
	if cap(h.sem) != 2 {
		t.Fatalf("semaphore capacity = %d, want 2", cap(h.sem))
	}
	if err := h.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "waits for a free slot"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Hash while saturated = %v, want a deadline error", err)
	}
	if _, _, err := h.Verify(ctx, "waits for a free slot", "$argon2id$v=19$m=64,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$daAoTfkIl8+qEluEDo2fBoFDUazt7/FB9noi3CGwjek"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Verify while saturated = %v, want a deadline error", err)
	}
	if err := h.DummyVerify(ctx, "waits for a free slot"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DummyVerify while saturated = %v, want a deadline error", err)
	}
	h.release()
	if _, err := h.Hash(t.Context(), "a slot is free again"); err != nil {
		t.Fatalf("Hash after releasing a slot failed: %v", err)
	}
	h.release()
}

func TestComputationsNeverExceedTheLimit(t *testing.T) {
	const limit = 3
	h := newTestHasher(t, fastParams, limit)
	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if err := h.acquire(t.Context()); err != nil {
				t.Error(err)
				return
			}
			now := running.Add(1)
			for {
				seen := peak.Load()
				if now <= seen || peak.CompareAndSwap(seen, now) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			running.Add(-1)
			h.release()
		})
	}
	wg.Wait()
	if peak.Load() > limit {
		t.Fatalf("saw %d concurrent computations, limit is %d", peak.Load(), limit)
	}
}

func TestDummyVerifyDoesTheWorkOfARealVerify(t *testing.T) {
	h := newTestHasher(t, Params{Memory: 4096, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, 1)
	encoded, err := h.Hash(t.Context(), "timing reference value")
	if err != nil {
		t.Fatal(err)
	}
	measure := func(run func()) time.Duration {
		best := time.Hour
		for range 5 {
			start := time.Now()
			run()
			best = min(best, time.Since(start))
		}
		return best
	}
	verifyCost := measure(func() { _, _, _ = h.Verify(t.Context(), "timing reference value", encoded) })
	dummyCost := measure(func() { _ = h.DummyVerify(t.Context(), "timing reference value") })
	if dummyCost < verifyCost/3 || dummyCost > verifyCost*3 {
		t.Fatalf("DummyVerify took %v and Verify took %v; they must cost about the same", dummyCost, verifyCost)
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key := []byte("0123456789abcdef0123456789abcdef")
	encoded := encode(fastParams, salt, key)
	params, gotSalt, gotKey, err := decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if params != fastParams || string(gotSalt) != string(salt) || string(gotKey) != string(key) {
		t.Fatalf("decode(encode(x)) changed the data: %+v %q %q", params, gotSalt, gotKey)
	}
}

func FuzzHashVerify(f *testing.F) {
	h := newTestHasher(f, Params{Memory: 8, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}, 4)
	for _, seed := range []string{"", "a", "password", "пароль", "ｐａｓｓ", "\x00\xff", strings.Repeat("x", 300), "ﬁ"} {
		f.Add(seed, seed+"!")
	}
	f.Fuzz(func(t *testing.T, password, other string) {
		encoded, err := h.Hash(t.Context(), password)
		if err != nil {
			if !errors.Is(err, ErrTooLong) {
				t.Fatalf("Hash failed unexpectedly: %v", err)
			}
			return
		}
		ok, needsRehash, err := h.Verify(t.Context(), password, encoded)
		if err != nil || !ok || needsRehash {
			t.Fatalf("round trip failed: ok:%v rehash:%v err:%v", ok, needsRehash, err)
		}
		ok, _, err = h.Verify(t.Context(), other, encoded)
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}
		equivalent := Normalize(password) == Normalize(other) && len(other) <= maxInputBytes
		if ok != equivalent {
			t.Fatalf("Verify(%q) = %v for a hash of %q, but equivalence is %v", other, ok, password, equivalent)
		}
	})
}

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"", "$", "$argon2id$v=19$m=64,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$daAoTfkIl8+qEluEDo2fBoFDUazt7/FB9noi3CGwjek",
		"$argon2id$v=19$m=4294967295,t=4294967295,p=255$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		params, salt, key, err := decode(encoded)
		if err != nil {
			return
		}
		if params.validate() != nil || len(salt) != int(params.SaltLength) || len(key) != int(params.KeyLength) {
			t.Fatalf("decode accepted an inconsistent hash: %+v", params)
		}
	})
}
