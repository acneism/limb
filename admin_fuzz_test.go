package limb

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/identifier/phone"
	"github.com/acneism/limb/store"
)

var userOrders = []UserOrder{UserOrderCreated, UserOrderLastLogin, UserOrderStatus}

func newFuzzAuth(f *testing.F, opts ...Option) *Auth {
	f.Helper()
	all := append([]Option{WithAutoMigrate(), WithLogger(discardingLogger())}, opts...)
	a, err := NewWithStore(newTestMemory(), []byte(testKey), all...)
	if err != nil {
		f.Fatalf("NewWithStore failed: %v", err)
	}
	a.hasher = newHasher(f, weakParams)
	f.Cleanup(func() { _ = a.Shutdown(context.Background()) })
	return a
}

func keptMoment(at time.Time) bool {
	return !at.IsZero() && at.Location() == time.UTC && at.Year() >= firstYear && at.Year() <= lastYear
}

func cursorText(text string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(text))
}

func FuzzUserCursor(f *testing.F) {
	for _, seed := range []string{
		"", "x", "!!", cursorText(`{}`), cursorText(`null`), cursorText(`[]`),
		cursorText(`{"o":"created","i":"x","c":5}`), cursorText(`{"o":"created","d":true,"i":"x","c":1700000000000000}`),
		cursorText(`{"o":"created","i":"x"}`), cursorText(`{"o":"created","i":"x","c":0}`),
		cursorText(`{"o":"created","i":"x","c":-62135596800000000}`), cursorText(`{"o":"created","i":"x","c":253402300800000000}`),
		cursorText(`{"o":"created","i":"x","c":9223372036854775807}`), cursorText(`{"o":"created","i":"","c":5}`),
		cursorText(`{"o":"created","i":"` + strings.Repeat("a", store.MaxIDLength+1) + `","c":5}`),
		cursorText(`{"o":"created","i":"a\u0000b","c":5}`), cursorText(`{"o":"created","i":"\ud800","c":5}`),
		cursorText(`{"o":"last_login","i":"x"}`), cursorText(`{"o":"last_login","i":"x","l":5}`),
		cursorText(`{"o":"last_login","d":true,"i":"x","l":-9223372036854775808}`),
		cursorText(`{"o":"status","i":"x","s":"blocked"}`), cursorText(`{"o":"status","i":"x","s":"gone"}`),
		cursorText(`{"o":"status","i":"x"}`), cursorText(`{"o":"created","i":"x","c":5,"s":"` + strings.Repeat("a", longestCursor) + `"}`),
		encodeUserCursor(store.User{ID: "user", CreatedAt: time.UnixMicro(1700000000123456)}, UserOrderCreated, false),
		encodeUserCursor(store.User{ID: "user", LastLoginAt: time.UnixMicro(1700000000123456)}, UserOrderLastLogin, true),
		encodeUserCursor(store.User{ID: "user", Status: store.StatusBlocked}, UserOrderStatus, false),
	} {
		for which := range userOrders {
			f.Add(seed, uint8(which), false)
			f.Add(seed, uint8(which), true)
		}
	}
	f.Fuzz(func(t *testing.T, text string, which uint8, descending bool) {
		order := userOrders[int(which)%len(userOrders)]
		after, err := decodeUserCursor(text, order, descending)
		if err != nil {
			var invalid *ValidationError
			if !errors.As(err, &invalid) || invalid.Field != "cursor" || invalid.Reason == "" {
				t.Fatalf("decodeUserCursor(%q) = %v, want a *ValidationError for the cursor", text, err)
			}
			return
		}
		if after == nil || after.ID == "" || len(after.ID) > store.MaxIDLength || len(text) > longestCursor {
			t.Fatalf("decodeUserCursor accepted %q as %+v", text, after)
		}
		switch order {
		case UserOrderCreated:
			if !keptMoment(after.CreatedAt) {
				t.Fatalf("the cursor %q of the creation holds the moment %v", text, after.CreatedAt)
			}
		case UserOrderLastLogin:
			if !after.LastLoginAt.IsZero() && !keptMoment(after.LastLoginAt) {
				t.Fatalf("the cursor %q of the last sign-in holds the moment %v", text, after.LastLoginAt)
			}
		case UserOrderStatus:
			if !validStatus(after.Status) {
				t.Fatalf("the cursor %q of the status holds the status %q", text, after.Status)
			}
		}
		for _, other := range userOrders {
			if _, err = decodeUserCursor(text, other, descending); other != order && err == nil {
				t.Fatalf("the cursor %q of the order %s was accepted for the order %s", text, order, other)
			}
		}
		if _, err = decodeUserCursor(text, order, !descending); err == nil {
			t.Fatalf("the cursor %q of the direction %v was accepted for the other direction", text, descending)
		}
		again, err := decodeUserCursor(encodeUserCursor(*after, order, descending), order, descending)
		if err != nil || !samePlace(*after, *again, order) {
			t.Fatalf("the cursor %q came back as %+v, %v after it was written again from %+v", text, again, err, after)
		}
	})
}

func samePlace(x, y store.User, order UserOrder) bool {
	if x.ID != y.ID {
		return false
	}
	switch order {
	case UserOrderCreated:
		return x.CreatedAt.Equal(y.CreatedAt)
	case UserOrderLastLogin:
		return x.LastLoginAt.Equal(y.LastLoginAt)
	case UserOrderStatus:
		return x.Status == y.Status
	}
	return false
}

func FuzzAuditCursor(f *testing.F) {
	for _, seed := range []string{
		"", "x", "!!", cursorText(`{}`), cursorText(`null`), cursorText(`{"t":5,"i":"x"}`), cursorText(`{"t":0,"i":"x"}`),
		cursorText(`{"t":5}`), cursorText(`{"i":"x"}`), cursorText(`{"t":-62135596800000000,"i":"x"}`),
		cursorText(`{"t":253402300799999999,"i":"x"}`), cursorText(`{"t":253402300800000000,"i":"x"}`),
		cursorText(`{"t":9223372036854775807,"i":"x"}`), cursorText(`{"t":-9223372036854775808,"i":"x"}`),
		cursorText(`{"t":5,"i":"` + strings.Repeat("a", store.MaxIDLength+1) + `"}`), cursorText(`{"t":5,"i":"a\u0000b"}`),
		cursorText(`{"t":5,"i":"x","x":"` + strings.Repeat("a", longestCursor) + `"}`),
		encodeAuditCursor(store.AuditRecord{At: time.UnixMicro(1700000000123456), ID: "00000000-0000-7000-8000-000000000001"}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		after, err := decodeAuditCursor(text)
		if err != nil {
			var invalid *ValidationError
			if !errors.As(err, &invalid) || invalid.Field != "cursor" || invalid.Reason == "" {
				t.Fatalf("decodeAuditCursor(%q) = %v, want a *ValidationError for the cursor", text, err)
			}
			return
		}
		if after == nil || after.ID == "" || len(after.ID) > store.MaxIDLength || len(text) > longestCursor || !keptMoment(after.At) {
			t.Fatalf("decodeAuditCursor accepted %q as %+v", text, after)
		}
		again, err := decodeAuditCursor(encodeAuditCursor(*after))
		if err != nil || again.ID != after.ID || !again.At.Equal(after.At) {
			t.Fatalf("the cursor %q came back as %+v, %v after it was written again from %+v", text, again, err, after)
		}
	})
}

func FuzzUserSearch(f *testing.F) {
	a := newFuzzAuth(f, WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username(), phone.Number("RU")))
	for _, seed := range []string{
		"", "   ", "a", "an", "ann", "ANN", "ann@example.com", "Ann@Example.COM", " ann ", "+7 (916) 123-45-67", "8 916 123 45 67", "+7916",
		"+7 (9", "+7 (", "(916)", "916-12", "50%", "50_", "50!", "a!", `a\`, "%", "_", "!", "ÅNN", "ǅab", "i̇ab", "ßab@example.com",
		"\x00ab", "a\xffb", "a b", "٣٣٣", "１２３", "ａｂｃ", "user@пример.рф", "xn--e1afmkfd", strings.Repeat("a", longestSearch),
		strings.Repeat("a", longestSearch+1), strings.Repeat("я", longestSearch), strings.Repeat("я", longestSearch+1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		var q store.UserQuery
		found, err := a.applySearch(&q, text)
		trimmed := strings.TrimSpace(text)
		if tooLong := utf8.RuneCountInString(trimmed) > longestSearch; tooLong {
			var invalid *ValidationError
			if !errors.As(err, &invalid) || invalid.Field != "search" {
				t.Fatalf("a search of %d characters = %v, want a *ValidationError for the search", utf8.RuneCountInString(trimmed), err)
			}
			return
		}
		if err != nil {
			t.Fatalf("applySearch(%q) failed: %v", text, err)
		}
		switch {
		case trimmed == "":
			if !found || q.ValuePrefix != "" || len(q.Identifiers) != 0 {
				t.Fatalf("an empty search = %+v, %v; want no condition", q, found)
			}
		case utf8.RuneCountInString(lightNormalize(trimmed)) >= shortestPrefix:
			if !found || q.ValuePrefix == "" || len(q.Identifiers) != 0 {
				t.Fatalf("the search %q = %+v, %v; want a prefix", text, q, found)
			}
		default:
			if q.ValuePrefix != "" || found != (len(q.Identifiers) > 0) {
				t.Fatalf("the search %q = %+v, %v; want exact values or nothing", text, q, found)
			}
			for _, ref := range q.Identifiers {
				kind, declared := a.known[ref.Type]
				if !declared {
					t.Fatalf("the search %q looks for the undeclared type %q", text, ref.Type)
				}
				if value, normalizeErr := kind.Normalize(trimmed); normalizeErr != nil || value != ref.Value {
					t.Fatalf("the search %q looks for %q of %s, but it is %q, %v", text, ref.Value, ref.Type, value, normalizeErr)
				}
			}
			if len(q.Identifiers) > len(a.types) {
				t.Fatalf("the search %q looks for %d values of %d types", text, len(q.Identifiers), len(a.types))
			}
		}
		if typed := typedNumber(lightNormalize(trimmed)); typed != "" {
			if strings.Trim(typed, "+0123456789") != "" || strings.LastIndexByte(typed, '+') > 0 || len(typed) > len(lightNormalize(trimmed)) {
				t.Fatalf("typedNumber(%q) = %q, want digits and a leading plus", trimmed, typed)
			}
		}
	})
}

func FuzzListUsers(f *testing.F) {
	a := newFuzzAuth(f, emailAndUsername())
	clock := newFakeClock()
	a.now = clock.now
	ctx := context.Background()
	for i, name := range []string{"ann", "bob", "cara", "dan", "eve", "fifty", "50xoff"} {
		user, err := a.Register(ctx, Registration{Identifiers: map[string]string{"email": name + "@example.com", "username": name + "_u"}, Password: goodPassword})
		if err != nil {
			f.Fatalf("Register failed: %v", err)
		}
		clock.advance(time.Hour)
		switch i {
		case 2:
			err = a.Admin().BlockUser(ctx, user.ID, "spam", time.Time{})
		case 3:
			err = a.Admin().DeleteUser(ctx, user.ID)
		}
		if err != nil {
			f.Fatalf("the setup of user %d failed: %v", i, err)
		}
	}
	for _, seed := range []struct {
		search, cursor, order, statuses, via string
		limit                                int16
		flags                                uint8
		from, before                         int64
	}{
		{"", "", "", "", "", 0, 0, 0, 0},
		{"ann", "", "created", "active", "api", 2, 1, 0, 0},
		{"50", "", "last_login", "active,blocked", "", 3, 2, 1, 1 << 60},
		{"b", cursorText(`{"o":"status","i":"x","s":"active"}`), "status", "", "admin", 1, 0, -1, 0},
		{"ann@example.com", cursorText(`{"o":"created","i":"x","c":5}`), "", "deleted", "signup", 200, 4, 0, 0},
		{"%", "", "created", "gone", "", 1, 0, 0, 0},
		{"", "", "name", "", "", 1, 0, 0, 0},
		{"", "", "", "", "magic", 1, 0, 0, 0},
		{"", "", "", "", "", -1, 0, 0, 0},
		{"", "", "", "", "", 201, 0, 0, 0},
		{"", "", "", "", "", 5, 8, 253402300800000000, 0},
		{"", "", "", "", "", 5, 8, 0, 9223372036854775807},
		{"", "", "", "", "", 5, 8, -9223372036854775808, 0},
		{"", "x", "", "", "", 5, 0, 0, 0},
	} {
		f.Add(seed.search, seed.cursor, seed.order, seed.statuses, seed.via, seed.limit, seed.flags, seed.from, seed.before)
	}
	f.Fuzz(func(t *testing.T, search, cursor, order, statuses, via string, limit int16, flags uint8, from, before int64) {
		filter := UserFilter{
			Search: search, Cursor: cursor, Order: UserOrder(order), CreatedVia: via, Limit: int(limit),
			Descending: flags&1 != 0, NeverLoggedIn: flags&2 != 0,
		}
		if statuses != "" {
			for _, status := range strings.Split(statuses, ",") {
				filter.Statuses = append(filter.Statuses, Status(status))
			}
		}
		switch flags >> 2 & 3 {
		case 1:
			confirmed := true
			filter.Confirmed = &confirmed
		case 2:
			confirmed := false
			filter.Confirmed = &confirmed
		}
		if flags&8 != 0 {
			if from != 0 {
				filter.CreatedFrom = time.UnixMicro(from).UTC()
			}
			if before != 0 {
				filter.CreatedBefore = time.UnixMicro(before).UTC()
			}
		}
		page, err := a.Admin().ListUsers(ctx, filter)
		if err != nil {
			var invalid *ValidationError
			if !errors.As(err, &invalid) || invalid.Field == "" || invalid.Reason == "" {
				t.Fatalf("ListUsers(%+v) = %v, want a *ValidationError", filter, err)
			}
			return
		}
		pageSize := filter.Limit
		if pageSize == 0 {
			pageSize = defaultUsersPage
		}
		if pageSize < len(page.Users) {
			t.Fatalf("ListUsers(%+v) returned %d users for the limit %d", filter, len(page.Users), pageSize)
		}
		seen := map[UserID]bool{}
		for _, u := range page.Users {
			if u.ID == "" || seen[u.ID] {
				t.Fatalf("ListUsers(%+v) returned the user %q twice or without an ID", filter, u.ID)
			}
			seen[u.ID] = true
		}
		if filter.Order == "" || filter.Order == UserOrderCreated {
			sorted := slices.IsSortedFunc(page.Users, func(x, y ManagedUser) int {
				if filter.Descending {
					x, y = y, x
				}
				return x.CreatedAt.Compare(y.CreatedAt)
			})
			if !sorted {
				t.Fatalf("ListUsers(%+v) is not ordered by the creation: %+v", filter, page.Users)
			}
		}
		if page.Next == "" {
			return
		}
		next := filter
		next.Cursor = page.Next
		following, err := a.Admin().ListUsers(ctx, next)
		if err != nil {
			t.Fatalf("the cursor %q of the page that ListUsers(%+v) made does not continue the list: %v", page.Next, filter, err)
		}
		for _, u := range following.Users {
			if seen[u.ID] {
				t.Fatalf("the user %q is on the page and on the page that follows it", u.ID)
			}
		}
	})
}

func FuzzSetUserIdentifier(f *testing.F) {
	a := newFuzzAuth(f, WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username(), phone.Number("RU")))
	ctx := context.Background()
	user, err := a.Register(ctx, Registration{Identifiers: map[string]string{"email": "ann@example.com", "username": "ann_a"}, Password: goodPassword})
	if err != nil {
		f.Fatal(err)
	}
	if _, err = a.Register(ctx, Registration{Identifiers: map[string]string{"email": "bob@example.com", "username": "bob_b", "phone": "+7 916 000 00 01"}, Password: goodPassword}); err != nil {
		f.Fatal(err)
	}
	types := []string{"email", "username", "phone"}
	for which := range types {
		for _, seed := range []string{
			"", "  ", "ann@example.com", "Ann@Example.COM", " new@example.com ", "bob@example.com", "bob_b", "BOB_B", "ann_a", "new_name",
			"+7 916 000 00 01", "8 (916) 000-00-01", "+7 916 000 00 02", "+1", "x@", "@x", "a b@example.com", "пример@пример.рф", "a\x00b", "a\xffb",
			strings.Repeat("a", 300), strings.Repeat("a", 64) + "@example.com", "ex́ample@example.com",
		} {
			f.Add(uint8(which), seed)
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, value string) {
		typ := types[int(which)%len(types)]
		before, err := a.Admin().User(ctx, user.ID)
		if err != nil {
			t.Fatalf("User failed: %v", err)
		}
		err = a.Admin().SetUserIdentifier(ctx, user.ID, typ, value)
		after, readErr := a.Admin().User(ctx, user.ID)
		if readErr != nil {
			t.Fatalf("User failed: %v", readErr)
		}
		kind := a.known[typ]
		normalized, normalizeErr := kind.Normalize(strings.TrimSpace(value))
		var invalid *ValidationError
		switch {
		case err == nil:
			if normalizeErr != nil || strings.TrimSpace(value) == "" {
				t.Fatalf("SetUserIdentifier accepted %q for %s", value, typ)
			}
			if got := valuesOfType(after, typ); !slices.Equal(got, []string{normalized}) {
				t.Fatalf("after %q the user has %v of %s, want [%q]", value, got, typ, normalized)
			}
			if err = a.Admin().SetUserIdentifier(ctx, user.ID, typ, value); err != nil {
				t.Fatalf("the same value %q set again failed: %v", value, err)
			}
		case errors.Is(err, ErrIdentifierTaken):
			if normalizeErr != nil {
				t.Fatalf("a value %q that cannot be normalized is taken: %v", value, normalizeErr)
			}
			if !slices.Equal(valuesOfType(before, typ), valuesOfType(after, typ)) {
				t.Fatalf("the %s of the user changed from %v to %v though the value is taken", typ, valuesOfType(before, typ), valuesOfType(after, typ))
			}
		case errors.As(err, &invalid):
			if normalizeErr == nil && strings.TrimSpace(value) != "" {
				t.Fatalf("SetUserIdentifier refused %q for %s, which normalizes to %q: %v", value, typ, normalized, err)
			}
			if invalid.Field != typ || !slices.Equal(valuesOfType(before, typ), valuesOfType(after, typ)) {
				t.Fatalf("the refusal %+v of %q changed the user from %+v to %+v", invalid, value, before.Identifiers, after.Identifiers)
			}
		default:
			t.Fatalf("SetUserIdentifier(%s, %q) = %v", typ, value, err)
		}
		if len(valuesOfType(after, "email")) != 1 || len(valuesOfType(after, "username")) > 1 || len(valuesOfType(after, "phone")) > 1 {
			t.Fatalf("the user has the identifiers %+v", after.Identifiers)
		}
	})
}

func valuesOfType(u ManagedUser, typ string) []string {
	var values []string
	for _, i := range u.Identifiers {
		if i.Type == typ {
			values = append(values, i.Value)
		}
	}
	return values
}

func FuzzBlockReason(f *testing.F) {
	a := newFuzzAuth(f, emailAndUsername())
	clock := newFakeClock()
	a.now = clock.now
	ctx := context.Background()
	user, err := a.Register(ctx, Registration{Identifiers: map[string]string{"email": "ann@example.com", "username": "ann_a"}, Password: goodPassword})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"", " ", "spam", "  spam  ", "line\nbreak", "tab\tbed", "a\xffb", "a\x00b", "a b", "a\u0085b", "бан за спам", strings.Repeat("a", store.MaxBlockedReasonLength),
		strings.Repeat("a", store.MaxBlockedReasonLength+1), strings.Repeat("я", store.MaxBlockedReasonLength/2), strings.Repeat("я", store.MaxBlockedReasonLength/2+1),
		"\U0001F600", "a\u200bb",
	} {
		f.Add(seed, int32(0), false)
		f.Add(seed, int32(60), true)
		f.Add(seed, int32(-60), true)
	}
	f.Fuzz(func(t *testing.T, reason string, minutes int32, withEnd bool) {
		var until time.Time
		if withEnd {
			until = clock.now().Add(time.Duration(minutes) * time.Minute)
		}
		err := a.Admin().BlockUser(ctx, user.ID, reason, until)
		trimmed := strings.TrimSpace(reason)
		reasonFine := trimmed != "" && len(trimmed) <= store.MaxBlockedReasonLength && utf8.ValidString(trimmed) && !hasControl(trimmed)
		endFine := !withEnd || minutes > 0
		var invalid *ValidationError
		switch {
		case err == nil:
			if !reasonFine || !endFine {
				t.Fatalf("BlockUser accepted the reason %q and the end %v", reason, until)
			}
			card, cardErr := a.Admin().User(ctx, user.ID)
			if cardErr != nil || card.Status != StatusBlocked || card.BlockedReason != trimmed || !utf8.ValidString(card.BlockedReason) {
				t.Fatalf("after the block with %q the card is %+v, %v", reason, card, cardErr)
			}
			if err = a.Admin().UnblockUser(ctx, user.ID); err != nil {
				t.Fatalf("UnblockUser failed: %v", err)
			}
		case errors.As(err, &invalid):
			if reasonFine && endFine {
				t.Fatalf("BlockUser refused the reason %q and the end %v: %v", reason, until, err)
			}
			if want := map[bool]string{false: "reason", true: "until"}[reasonFine]; invalid.Field != want {
				t.Fatalf("BlockUser(%q, %v) named the field %q, want %q: %v", reason, until, invalid.Field, want, err)
			}
		default:
			t.Fatalf("BlockUser(%q, %v) = %v", reason, until, err)
		}
		card, cardErr := a.Admin().User(ctx, user.ID)
		if cardErr != nil || card.Status != StatusActive {
			t.Fatalf("the user is left as %+v, %v", card, cardErr)
		}
	})
}
