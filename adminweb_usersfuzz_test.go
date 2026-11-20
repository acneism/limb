package limb

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

var listLinkPattern = regexp.MustCompile(`href="(/admin/(?:users|audit)\?[^"]*)"`)

type fuzzedPeople struct {
	*fuzzedAdmin
	slots    [3]UserID
	sessions [3]string
}

func newFuzzedPeople(f *testing.F) *fuzzedPeople {
	f.Helper()
	sender := senderFunc(func(context.Context, Message) error { return nil })
	return &fuzzedPeople{fuzzedAdmin: newFuzzedAdmin(f, emailAndUsername(), WithSender(sender), WithResetURL("https://app.example.com/reset"))}
}

func (fz *fuzzedPeople) prepare(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	a := fz.auth
	for _, id := range fz.slots {
		if id != "" {
			if err := a.eraseUser(ctx, apiActor, id); err != nil && !errors.Is(err, ErrUserNotFound) {
				t.Fatal(err)
			}
		}
	}
	for {
		removed, err := a.store.Audit().DeleteBefore(ctx, a.tenant, fz.clock.now().Add(time.Hour), store.MaxAuditPage)
		if err != nil {
			t.Fatal(err)
		}
		if removed < store.MaxAuditPage {
			break
		}
	}
	admin := a.Admin()
	first, err := admin.CreateUser(ctx, NewUser{Identifiers: map[string]string{"email": "first@example.com", "username": "first_user"}, Password: goodPassword, KeepPassword: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := admin.CreateUser(ctx, NewUser{Identifiers: map[string]string{"email": "second@example.com", "username": "second_user"}, Password: goodPassword})
	if err != nil {
		t.Fatal(err)
	}
	if err = admin.VerifyUserIdentifier(ctx, second.ID, "email"); err != nil {
		t.Fatal(err)
	}
	if err = admin.BlockUser(ctx, second.ID, "fuzz", fz.clock.now().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	third, err := admin.InviteUser(ctx, Invitation{Identifiers: map[string]string{"email": "third@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	fz.slots = [3]UserID{first.ID, second.ID, third.ID}
	login, err := a.Login(ctx, Credentials{Login: "first_user", Password: goodPassword, IP: testIP, UserAgent: "fuzz", Kind: SessionCookie})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Login(ctx, Credentials{Login: "first_user", Password: goodPassword, IP: testIP, UserAgent: "fuzz", Kind: SessionToken}); err != nil {
		t.Fatal(err)
	}
	fz.sessions = [3]string{login.Principal.SessionID, "none", "none"}
}

func (fz *fuzzedPeople) fingerprint(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	var out strings.Builder
	page, err := fz.auth.listUsers(ctx, UserFilter{Limit: largestUsersPage})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range page.Users {
		fmt.Fprintf(&out, "%s|%s|%v|%v|%s|%d|", u.ID, u.Status, u.HasPassword, u.MustChangePassword, u.BlockedReason, u.BlockedUntil.UnixMicro())
		for _, i := range u.Identifiers {
			fmt.Fprintf(&out, "%s=%s/%v;", i.Type, i.Value, !i.VerifiedAt.IsZero())
		}
		sessions, sessionsErr := fz.auth.userSessions(ctx, string(u.ID), "")
		if sessionsErr != nil {
			t.Fatal(sessionsErr)
		}
		fmt.Fprintf(&out, "|%d\n", len(sessions))
	}
	records, err := fz.auth.store.Audit().List(ctx, store.AuditQuery{TenantID: fz.auth.tenant, Limit: store.MaxAuditPage})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&out, "audit=%d", len(records))
	return out.String()
}

func (fz *fuzzedPeople) checkState(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, id := range fz.slots {
		user, err := fz.auth.managedUserByID(ctx, id)
		if errors.Is(err, ErrUserNotFound) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		sessions, err := fz.auth.userSessions(ctx, string(id), "")
		if err != nil {
			t.Fatal(err)
		}
		if (user.Status == StatusBlocked || user.Status == StatusDeleted) && len(sessions) != 0 {
			t.Fatalf("the user %s is %s and has %d sessions in use", id, user.Status, len(sessions))
		}
		if user.Status != StatusDeleted && len(user.Identifiers) == 0 {
			t.Fatalf("the user %s has no value to sign in with", id)
		}
	}
}

func FuzzAdminUserActions(f *testing.F) {
	fz := newFuzzedPeople(f)
	const form = "application/x-www-form-urlencoded"
	type seed struct {
		method, target, contentType, body, origin string
		slot                                      uint8
		token                                     bool
	}
	for _, s := range []seed{
		{"GET", "/users", "", "", "", 0, false},
		{"GET", "/users?status=blocked&order=last_login&dir=asc&limit=10", "", "", "", 0, false},
		{"GET", "/users/new", "", "", "", 0, false},
		{"GET", "/users/{id}", "", "", "", 0, false},
		{"GET", "/users/{id}?done=blocked&lang=ru", "", "", "", 1, false},
		{"GET", "/audit?user={id}&limit=10", "", "", "", 0, false},
		{"POST", "/users/{id}/block", form, "reason=spam&until=2031-01-02", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/block", form, "reason=&until=nope", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/unblock", form, "", fuzzOrigin, 1, true},
		{"POST", "/users/{id}/sessions/end", form, "session={session}", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/sessions/end-all", form, "", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/delete", form, "confirm=first@example.com", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/delete", form, "confirm=nobody", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/restore", form, "", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/password/link", form, "language=ru", fuzzOrigin, 1, true},
		{"POST", "/users/{id}/password/temporary", form, "language=en", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/identifiers/set", form, "type=email&value=Changed%40Example.com", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/identifiers/set", form, "type=username&value=a", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/identifiers/remove", form, "type=username", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/identifiers/remove", form, "type=email", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/identifiers/verify", form, "type=email", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/invitation", form, "language=en", fuzzOrigin, 2, true},
		{"POST", "/users/new", form, "value.email=new%40example.com&value.username=new_one&password=a+long+enough+password&verified.email=1", fuzzOrigin, 0, true},
		{"POST", "/users/new", form, "mode=invite&value.email=invited%40example.com&language=ru", fuzzOrigin, 0, true},
		{"POST", "/users/new", form, "value.email=first%40example.com&password=short", fuzzOrigin, 0, true},
		{"POST", "/users/{id}/block", form, "reason=spam", "https://evil.example", 0, true},
		{"POST", "/users/{id}/block", "application/json", `{"reason":"spam"}`, fuzzOrigin, 0, true},
		{"DELETE", "/users/{id}", "", "", "", 0, false},
	} {
		f.Add(s.method, s.target, s.contentType, s.body, s.origin, s.slot, s.token)
	}
	f.Fuzz(func(t *testing.T, method, target, contentType, body, origin string, slot uint8, withToken bool) {
		if !strings.HasPrefix(target, "/") || len(body) > 40<<10 || len(target) > 2000 {
			return
		}
		fz.clock.advance(16 * time.Minute)
		fz.prepare(t)
		sessionSecret, token := fz.session(t)
		id := string(fz.slots[int(slot)%len(fz.slots)])
		replacer := strings.NewReplacer("{id}", id, "{session}", fz.sessions[int(slot)%len(fz.sessions)])
		target, body = replacer.Replace(target), replacer.Replace(body)
		if withToken {
			body += "&csrf=" + url.QueryEscape(token)
		}
		request, err := http.NewRequestWithContext(context.Background(), method, "http://app.example.com"+target, strings.NewReader(body))
		if err != nil {
			return
		}
		fz.calls++
		request.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1234", fz.calls>>16&255, fz.calls>>8&255, fz.calls&255)
		request.Header.Set("Cookie", "limb_admin="+sessionSecret)
		for name, value := range map[string]string{"Content-Type": contentType, "Origin": origin} {
			if value != "" {
				request.Header.Set(name, value)
			}
		}
		before := fz.fingerprint(t)
		recorder := httptest.NewRecorder()
		fz.handler.ServeHTTP(recorder, request)
		checkFuzzedAdminAnswer(t, recorder, method, target, sessionSecret)
		fz.checkState(t)
		safe := method == http.MethodGet || method == http.MethodHead
		if after := fz.fingerprint(t); (safe || recorder.Code >= http.StatusBadRequest) && after != before {
			t.Fatalf("%s %q answered %d and changed what it should not:\nbefore:\n%s\nafter:\n%s", method, target, recorder.Code, before, after)
		}
	})
}

type fuzzedLists struct {
	*fuzzedAdmin
	secret string
}

func newFuzzedLists(f *testing.F) *fuzzedLists {
	f.Helper()
	fz := newFuzzedAdmin(f, emailAndUsername())
	ctx := context.Background()
	for i := range 25 {
		name := "list" + strconv.Itoa(i)
		user, err := fz.auth.Admin().CreateUser(ctx, NewUser{Identifiers: map[string]string{"email": name + "@example.com", "username": name}, Password: goodPassword})
		if err != nil {
			f.Fatal(err)
		}
		switch i % 5 {
		case 1:
			err = fz.auth.Admin().BlockUser(ctx, user.ID, "fuzz", time.Time{})
		case 2:
			err = fz.auth.Admin().VerifyUserIdentifier(ctx, user.ID, "email")
		case 3:
			err = fz.auth.Admin().DeleteUser(ctx, user.ID)
		}
		if err != nil {
			f.Fatal(err)
		}
		fz.clock.advance(time.Hour)
	}
	return &fuzzedLists{fuzzedAdmin: fz}
}

func (fz *fuzzedLists) get(target string) *httptest.ResponseRecorder {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://app.example.com"+target, nil)
	if err != nil {
		return nil
	}
	request.RemoteAddr = "10.9.9.9:1234"
	request.Header.Set("Cookie", "limb_admin="+fz.secret)
	recorder := httptest.NewRecorder()
	fz.handler.ServeHTTP(recorder, request)
	return recorder
}

func FuzzAdminLists(f *testing.F) {
	fz := newFuzzedLists(f)
	for _, seed := range []string{
		"", "status=blocked&status=deleted", "confirmed=yes&via=api&never=1", "created_from=2026-01-01&created_to=2030-01-01&order=last_login&dir=asc&limit=10", "q=list1&order=status",
		"limit=10&dir=asc", "cursor=eyJvIjoiY3JlYXRlZCJ9", "status=%FF&limit=-1&order=%00", "q=" + strings.Repeat("%25", 200), "user=abc&action=user.blocked&from=2026-01-01&limit=10",
		"admin=a%2Fb", "action=nope", "from=2026-02-30", "to=9999-12-31", "lang=ru&limit=25",
	} {
		f.Add(seed, true)
		f.Add(seed, false)
	}
	f.Fuzz(func(t *testing.T, query string, users bool) {
		if len(query) > 2000 || strings.ContainsAny(query, "#\x00 \r\n") {
			return
		}
		if fz.secret == "" {
			fz.secret, _ = fz.session(t)
		}
		path := "/audit?"
		if users {
			path = "/users?"
		}
		recorder := fz.get(path + query)
		if recorder == nil {
			return
		}
		checkFuzzedAdminAnswer(t, recorder, "GET", path+query, fz.secret)
		switch recorder.Code {
		case http.StatusOK:
		case http.StatusBadRequest:
			if !strings.Contains(recorder.Body.String(), "A value in the search is not valid") {
				t.Fatalf("GET %s answered 400 without naming the value", path+query)
			}
			return
		case http.StatusSeeOther:
			return
		default:
			t.Fatalf("GET %s answered %d", path+query, recorder.Code)
		}
		for i, match := range listLinkPattern.FindAllStringSubmatch(recorder.Body.String(), -1) {
			if i == 8 {
				break
			}
			link := strings.TrimPrefix(html.UnescapeString(match[1]), adminMount)
			followed := fz.get(link)
			if followed == nil {
				t.Fatalf("GET %s answered 200 with a link to %s that is not a request", path+query, link)
			}
			if followed.Code != http.StatusOK {
				t.Fatalf("GET %s answered 200 with a link to %s that answers %d: %.200s", path+query, link, followed.Code, followed.Body.String())
			}
		}
	})
}
