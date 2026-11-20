package limb

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

func newPeopleInstances(t *testing.T, d *database, opts ...Option) (*peopleFixture, *peopleFixture) {
	t.Helper()
	w := newWebInstances(t, d, opts...)
	ids, names := map[string]UserID{}, map[UserID]string{}
	return &peopleFixture{webFixture: w.a, start: w.clock.now(), ids: ids, names: names}, &peopleFixture{webFixture: w.b, start: w.clock.now(), ids: ids, names: names}
}

func messagesOf(t *testing.T, sender *recordingSender, kind MessageKind, n int) []Message {
	t.Helper()
	var found []Message
	eventually(t, "the messages of a kind to be sent", func() bool {
		found = found[:0]
		for _, m := range sender.sent() {
			if m.Kind == kind {
				found = append(found, m)
			}
		}
		return len(found) >= n
	})
	return found
}

func enrollBoth(a, b *peopleFixture) {
	a.t.Helper()
	a.enroll()
	b.adopt(a.browser)
}

func TestBlockingAUserThroughTheBrowserEndsTheirAccessOnTheNextRequestOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		a, b := newPeopleInstances(t, d)
		a.add("ann")
		a.add("bob")
		enrollBoth(a, b)
		id := string(a.ids["ann"])
		cookie, token, other := a.userLogin("ann", SessionCookie), b.userLogin("ann", SessionToken), a.userLogin("bob", SessionCookie)
		for name, instance := range map[string]*peopleFixture{"a": a, "b": b} {
			if !instance.authenticated(cookie) || !instance.authenticated(token) || !instance.authenticated(other) {
				t.Fatalf("instance %s: a session does not work before the block", name)
			}
		}
		r := b.act("ann", "block", url.Values{"reason": {"seen on every database"}, "until": {"2026-10-01"}})
		if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users/"+id+"?done=blocked" {
			t.Fatalf("the block gave %d %q: %.300s", r.StatusCode, r.location(), r.body)
		}
		for name, instance := range map[string]*peopleFixture{"a": a, "b": b} {
			if instance.authenticated(cookie) || instance.authenticated(token) || !instance.authenticated(other) {
				t.Fatalf("instance %s: after the block the sessions of the user work, or a session of another user does not", name)
			}
		}
		if _, err := a.a.Refresh(t.Context(), token.Tokens.RefreshToken); err == nil {
			t.Fatal("a blocked user refreshes the tokens")
		}
		if _, err := b.a.Login(t.Context(), Credentials{Login: "ann", Password: goodPassword, IP: testIP, Kind: SessionCookie}); !errors.Is(err, ErrUserBlocked) {
			t.Fatalf("a blocked user signs in: %v", err)
		}
		card := a.get("/users/" + id)
		for _, want := range []string{`<span class="badge badge-blocked">Blocked</span>`, "seen on every database", `<time datetime="2026-10-01T00:00:00Z">`, "The user has no session in use.", "<td>User blocked</td>\n<td class=\"break\">root</td>"} {
			if !card.has(want) {
				t.Errorf("the card of the blocked user lacks %q", want)
			}
		}
		if got := b.listed("?status=blocked"); !slices.Equal(got, []string{"ann"}) {
			t.Errorf("the blocked users are %v", got)
		}
		record := recordsOf(t, a.a, audit.UserBlocked)
		if len(record) != 1 || record[0].ActorKind != store.ActorAdmin || record[0].ActorID != a.adminID() || record[0].IP != "127.0.0.1" || record[0].TargetUserID != id {
			t.Fatalf("the record of the block is %+v", record)
		}

		a.clock.advance(time.Minute)
		if r = a.act("ann", "unblock", url.Values{}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("lifting the block gave %d", r.StatusCode)
		}
		if _, err := b.a.Login(t.Context(), Credentials{Login: "ann", Password: goodPassword, IP: testIP, Kind: SessionCookie}); err != nil {
			t.Fatalf("a user whose block was lifted cannot sign in: %v", err)
		}
		a.clock.advance(time.Minute)
		if r = b.act("ann", "block", url.Values{"reason": {"until a day"}, "until": {"2026-09-14"}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("the second block gave %d", r.StatusCode)
		}
		if _, err := a.a.Login(t.Context(), Credentials{Login: "ann", Password: goodPassword, IP: testIP, Kind: SessionCookie}); !errors.Is(err, ErrUserBlocked) {
			t.Fatalf("a user blocked until a day signs in before it: %v", err)
		}
		a.clock.advance(72 * time.Hour)
		if _, err := a.a.Login(t.Context(), Credentials{Login: "ann", Password: goodPassword, IP: testIP, Kind: SessionCookie}); err != nil {
			t.Fatalf("a user whose block ran out cannot sign in: %v", err)
		}
	})
}

func TestTheListsOfTheWebAdministrationAreFilteredOrderedAndPagedOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		a, b := newPeopleInstances(t, d)
		var oldestFirst []string
		for i := range 23 {
			name := "u" + strconv.Itoa(i/10) + strconv.Itoa(i%10)
			a.add(name)
			oldestFirst = append(oldestFirst, name)
		}
		admin := a.a.Admin()
		if err := admin.BlockUser(t.Context(), a.ids["u02"], "spam", time.Time{}); err != nil {
			t.Fatal(err)
		}
		if err := admin.DeleteUser(t.Context(), a.ids["u03"]); err != nil {
			t.Fatal(err)
		}
		if err := admin.VerifyUserIdentifier(t.Context(), a.ids["u04"], "email"); err != nil {
			t.Fatal(err)
		}
		a.userLogin("u05", SessionCookie)
		a.clock.advance(time.Hour)
		a.userLogin("u06", SessionToken)
		if err := admin.BlockUser(t.Context(), a.ids["u07"], "later", a.clock.now().Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		a.clock.advance(time.Minute)
		enrollBoth(a, b)
		newestFirst := reversed(oldestFirst)

		for name, instance := range map[string]*peopleFixture{"a": a, "b": b} {
			var got []string
			var sizes []int
			path := "/users?limit=10"
			for page := 1; path != ""; page++ {
				r := instance.get(path)
				if r.StatusCode != http.StatusOK {
					t.Fatalf("instance %s: GET %s = %d: %.300s", name, path, r.StatusCode, r.body)
				}
				names := instance.namesIn(r)
				got, sizes = append(got, names...), append(sizes, len(names))
				path = hrefTo(t, r, "Next page")
				if page > 3 {
					t.Fatalf("instance %s: more than three pages", name)
				}
			}
			if !slices.Equal(got, newestFirst) || !slices.Equal(sizes, []int{10, 10, 3}) {
				t.Fatalf("instance %s: the pages hold %v users, the users are %v, want %v", name, sizes, got, newestFirst)
			}
		}
		if got := b.listed("?order=created&dir=asc&limit=200"); !slices.Equal(got, oldestFirst) {
			t.Errorf("the oldest first: %v", got)
		}
		for _, c := range []struct {
			name, query string
			want        []string
		}{
			{"blocked", "?status=blocked", []string{"u07", "u02"}},
			{"deleted", "?status=deleted", []string{"u03"}},
			{"blocked or deleted", "?status=blocked&status=deleted", []string{"u07", "u03", "u02"}},
			{"with a confirmed value", "?confirmed=yes", []string{"u04"}},
			{"created within days", "?created_from=2026-09-20&created_to=2026-09-22", []string{"u12", "u11", "u10"}},
			{"signed in on a day", "?login_from=2026-09-10&login_to=2026-09-10", nil},
			{"by a prefix", "?q=u13", []string{"u13"}},
			{"by a prefix of an address", "?q=U14@Example", []string{"u14"}},
		} {
			for name, instance := range map[string]*peopleFixture{"a": a, "b": b} {
				if got := instance.listed(c.query); !slices.Equal(got, c.want) {
					t.Errorf("instance %s, %s: GET /users%s lists %v, want %v", name, c.name, c.query, got, c.want)
				}
			}
		}
		if got := a.listed("?never=1&limit=200"); len(got) != 21 || slices.Contains(got, "u05") || slices.Contains(got, "u06") {
			t.Errorf("the users who never signed in are %v", got)
		}
		if got := b.listed("?order=last_login&dir=desc&limit=10"); len(got) != 10 || !slices.Equal(got[:2], []string{"u06", "u05"}) {
			t.Errorf("by the last sign-in: %v", got)
		}
		if got := a.listed("?order=last_login&dir=asc&limit=10"); !slices.Equal(got[:2], []string{"u05", "u06"}) {
			t.Errorf("by the last sign-in, ascending: %v", got)
		}
		statuses := map[string]string{"u02": "blocked", "u03": "deleted", "u07": "blocked"}
		var order []string
		for _, name := range b.listed("?order=status&dir=asc&limit=200") {
			status := statuses[name]
			if status == "" {
				status = "active"
			}
			order = append(order, status)
		}
		if !slices.IsSorted(order) || len(order) != 23 {
			t.Errorf("by the status: %v", order)
		}

		catalog, err := adminui.NewCatalog(nil)
		if err != nil {
			t.Fatal(err)
		}
		english := adminui.NewPage(catalog, "en")
		records, err := a.a.store.Audit().List(t.Context(), store.AuditQuery{TenantID: a.a.tenant, Limit: store.MaxAuditPage})
		if err != nil || len(records) < 30 {
			t.Fatalf("the audit log holds %d records, %v", len(records), err)
		}
		var want []string
		for _, record := range records {
			want = append(want, english.T("audit.action."+record.Action))
		}
		var seen []string
		path := "/audit?limit=100"
		for page := 1; path != ""; page++ {
			r := b.get(path)
			if r.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d: %.300s", path, r.StatusCode, r.body)
			}
			for _, m := range auditLabelPattern.FindAllStringSubmatch(r.body, -1) {
				seen = append(seen, m[1])
			}
			path = hrefTo(t, r, "Next page")
			if page > 6 {
				t.Fatal("more than six pages")
			}
		}
		if !slices.Equal(seen, want) {
			t.Fatalf("the pages of the audit log are %v, the log is %v", seen, want)
		}
		if got := a.auditLabels("?action=user.blocked&limit=10"); len(got) != 2 {
			t.Errorf("the blocks are %v", got)
		}
		if got := a.auditLabels("?user=" + string(a.ids["u03"]) + "&limit=200"); !slices.Contains(got, "User deleted") || !slices.Contains(got, "Account created") {
			t.Errorf("the records of the deleted user are %v", got)
		}
	})
}

func TestTheUsersAreManagedThroughTheBrowserOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		sender := &recordingSender{}
		a, b := newPeopleInstances(t, d, WithSender(sender), WithResetURL("https://app.example.com/reset"), WithServiceName("Acme"))
		a.add("ann")
		a.add("bob")
		a.confirm("ann")
		enrollBoth(a, b)
		ann := string(a.ids["ann"])
		login := func(instance *peopleFixture, who, password string) error {
			_, err := instance.a.Login(t.Context(), Credentials{Login: who, Password: password, IP: testIP, Kind: SessionCookie})
			return err
		}
		step := func() { a.clock.advance(time.Second) }

		session := a.userLogin("ann", SessionCookie)
		sessionID := session.Principal.SessionID
		b.userLogin("ann", SessionToken)
		if r := b.act("ann", "sessions/end", url.Values{"session": {sessionID}}); r.StatusCode != http.StatusSeeOther || a.authenticated(session) {
			t.Fatalf("ending one session gave %d, or the session works", r.StatusCode)
		}
		step()
		if r := b.act("ann", "sessions/end", url.Values{"session": {strings.Repeat("s", 500)}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("ending a session by an ID that is far too long gave %d", r.StatusCode)
		}
		step()
		if r := a.act("ann", "sessions/end-all", url.Values{}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("ending all the sessions gave %d", r.StatusCode)
		}
		if sessions, err := b.a.Admin().UserSessions(t.Context(), a.ids["ann"]); err != nil || len(sessions) != 0 {
			t.Fatalf("the sessions of the user are %v, %v", sessions, err)
		}

		step()
		if r := a.act("ann", "delete", url.Values{"confirm": {"ANN@example.com"}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("the deletion gave %d: %.300s", r.StatusCode, r.body)
		}
		if err := login(b, "ann", goodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a deleted user signs in: %v", err)
		}
		if _, err := b.a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "ann@example.com", "username": "other"}, Password: goodPassword}); !errors.Is(err, ErrIdentifierTaken) {
			t.Fatalf("the value of a deleted user is free: %v", err)
		}
		if card := b.get("/users/" + ann); !card.has("Restore the user") || !card.has(`<span class="badge badge-deleted">Deleted</span>`) {
			t.Fatalf("the card of a deleted user is wrong")
		}
		step()
		if r := b.act("ann", "restore", url.Values{}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("the restoring gave %d", r.StatusCode)
		}
		if err := login(a, "ann", goodPassword); err != nil {
			t.Fatalf("a restored user cannot sign in: %v", err)
		}

		step()
		if r := a.act("ann", "identifiers/set", url.Values{"type": {"email"}, "value": {"New.Ann@Example.com"}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("a change of the address gave %d: %.300s", r.StatusCode, r.body)
		}
		if r := b.act("ann", "identifiers/set", url.Values{"type": {"email"}, "value": {"bob@example.com"}}); r.StatusCode != http.StatusConflict {
			t.Fatalf("an address that another user has gave %d", r.StatusCode)
		}
		if r := b.act("ann", "identifiers/verify", url.Values{"type": {"email"}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("confirming gave %d", r.StatusCode)
		}
		if r := b.act("ann", "identifiers/remove", url.Values{"type": {"username"}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("removing the username gave %d", r.StatusCode)
		}
		if r := a.act("ann", "identifiers/set", url.Values{"type": {"username"}, "value": {"Ann_Again"}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("adding the username gave %d", r.StatusCode)
		}
		user, err := b.a.Admin().User(t.Context(), a.ids["ann"])
		if err != nil || len(user.Identifiers) != 2 || user.Identifiers[0].Value != "new.ann@example.com" || user.Identifiers[0].VerifiedAt.IsZero() || user.Identifiers[1].Value != "ann_again" {
			t.Fatalf("the values of the user are %+v, %v", user.Identifiers, err)
		}

		step()
		created := createdID(t, a.create(url.Values{"value.email": {"made@example.com"}, "value.username": {"made_by"}, "password": {goodPassword}, "verified.email": {"1"}}), "created")
		if err = login(b, "made_by", goodPassword); err != nil {
			t.Fatalf("a user that the administration made cannot sign in: %v", err)
		}
		if made, userErr := b.a.Admin().User(t.Context(), created); userErr != nil || !made.MustChangePassword || made.CreatedVia != "admin" || made.Identifiers[0].VerifiedAt.IsZero() {
			t.Fatalf("the user that was made is %+v, %v", made, userErr)
		}

		step()
		invited := createdID(t, b.create(url.Values{"mode": {"invite"}, "value.email": {"Ivan@Example.com"}, "language": {"ru"}}), "invited")
		first := messagesOf(t, sender, MessageInvitation, 1)[0]
		if first.To != "ivan@example.com" || first.Language != "ru" {
			t.Fatalf("the invitation is %+v", first)
		}
		step()
		if r := a.post("/users/"+string(invited)+"/invitation", url.Values{"csrf": {a.csrfOf(a.get("/users/" + string(invited)))}, "language": {"en"}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("sending the invitation again gave %d", r.StatusCode)
		}
		second := messagesOf(t, sender, MessageInvitation, 2)[1]
		if err = b.a.ResetPassword(t.Context(), ResetPasswordRequest{Token: tokenOf(second.Link), Password: chosen}); err != nil {
			t.Fatalf("the invitation does not work: %v", err)
		}
		if card := a.get("/users/" + string(invited)); card.has("Send the invitation again") || !card.has("<dd>set</dd>") {
			t.Fatalf("the card of a user who chose a password still waits for them")
		}

		step()
		if r := a.act("ann", "password/link", url.Values{"language": {"en"}}); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("a link gave %d: %.300s", r.StatusCode, r.body)
		}
		if link := messagesOf(t, sender, MessagePasswordReset, 1)[0]; link.To != "new.ann@example.com" {
			t.Fatalf("the link is %+v", link)
		}
		step()
		temporary := b.act("ann", "password/temporary", url.Values{"language": {"en"}})
		found := temporaryPattern.FindStringSubmatch(temporary.body)
		if temporary.StatusCode != http.StatusOK || found == nil {
			t.Fatalf("the temporary password gave %d: %.300s", temporary.StatusCode, temporary.body)
		}
		if err = login(a, "ann_again", found[1]); err != nil {
			t.Fatalf("the temporary password does not work: %v", err)
		}
		if err = login(a, "ann_again", goodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("the old password still works: %v", err)
		}

		want := map[string]int{
			audit.UserSessionEnded: 1, audit.UserSessionsEnded: 1, audit.UserDeleted: 1, audit.UserRestored: 1, audit.UserIdentifierChanged: 1, audit.UserIdentifierVerified: 1,
			audit.UserIdentifierRemoved: 1, audit.UserIdentifierAdded: 1, audit.UserInvited: 1, audit.UserInvitationResent: 1, audit.UserPasswordResetSent: 1, audit.UserPasswordTemporary: 1,
		}
		for action, count := range want {
			records := recordsOf(t, a.a, action)
			if len(records) != count {
				t.Errorf("%d records of %s, want %d", len(records), action, count)
			}
			for _, record := range records {
				if record.ActorKind != store.ActorAdmin || record.ActorID != a.adminID() || record.IP != "127.0.0.1" {
					t.Errorf("a record of %s is %+v, want it in the name of the administrator", action, record)
				}
			}
		}
		created2 := recordsOf(t, a.a, audit.UserCreated)
		madeByAdmin := 0
		for _, record := range created2 {
			if record.ActorKind == store.ActorAdmin && record.TargetUserID == string(created) {
				madeByAdmin++
			}
		}
		if madeByAdmin != 1 {
			t.Errorf("the creation of the user is recorded %d times in the name of the administrator", madeByAdmin)
		}
		page := a.get("/audit?admin=" + a.adminID() + "&limit=200")
		for _, label := range []string{
			"Session of the user ended", "User deleted", "User restored", "Value to sign in with changed", "Value marked as confirmed", "Value to sign in with removed",
			"Value to sign in with added", "User created by an administrator", "User invited", "Invitation sent again", "Link to reset the password sent", "Temporary password set",
		} {
			if !page.has("<td>" + label + "</td>") {
				t.Errorf("the audit log of the administrator lacks %q", label)
			}
		}
	})
}

func TestTheImmediateDeletionOfAUserThroughTheBrowserErasesThemOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		a, b := newPeopleInstances(t, d, WithImmediateDeletion())
		a.add("ann")
		a.add("bob")
		enrollBoth(a, b)
		a.userLogin("ann", SessionToken)
		r := b.act("ann", "delete", url.Values{"confirm": {"ann"}})
		if r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/users?done=erased" {
			t.Fatalf("the deletion gave %d %q: %.300s", r.StatusCode, r.location(), r.body)
		}
		if got := a.listed(""); !slices.Equal(got, []string{"bob"}) {
			t.Errorf("the users are %v", got)
		}
		if card := a.get("/users/" + string(a.ids["ann"])); card.StatusCode != http.StatusNotFound {
			t.Errorf("the card of an erased user is %d", card.StatusCode)
		}
		if _, err := b.a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "ann@example.com", "username": "ann"}, Password: goodPassword}); err != nil {
			t.Errorf("the values of an erased user are not free: %v", err)
		}
		if got := a.auditLabels("?action=user.deleted"); !slices.Equal(got, []string{"User deleted"}) {
			t.Errorf("the records of the deletion are %v", got)
		}
	})
}
