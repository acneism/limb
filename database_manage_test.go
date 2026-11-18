package limb

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func (i *instances) user(t *testing.T, a *Auth, name string) User {
	t.Helper()
	return mustRegister(t, a, map[string]string{"email": name + "@example.com", "username": name + "_n"}, goodPassword)
}

func (i *instances) signIn(t *testing.T, a *Auth, name string, kind SessionKind) Login {
	t.Helper()
	login, err := a.Login(t.Context(), Credentials{Login: name + "@example.com", Password: goodPassword, IP: testIP, UserAgent: testAgent, Kind: kind})
	if err != nil {
		t.Fatalf("Login of %s failed: %v", name, err)
	}
	return login
}

func (i *instances) can(t *testing.T, a *Auth, login Login) bool {
	t.Helper()
	var err error
	if login.Secret != "" {
		_, err = a.Authenticate(i.cookie(t, a, login.Secret))
	} else {
		_, err = a.Authenticate(i.bearer(t, login.Tokens.AccessToken))
	}
	if err != nil && !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate failed in another way than by refusing: %v", err)
	}
	return err == nil
}

func TestABlockEndsTheAccessOnTheOtherInstanceAtOnceOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		nina := in.user(t, in.a, "nina")
		cookie := in.signIn(t, in.a, "nina", SessionCookie)
		token := in.signIn(t, in.b, "nina", SessionToken)
		if !in.can(t, in.b, cookie) || !in.can(t, in.a, token) {
			t.Fatal("a session of one instance does not work on the other before the block")
		}
		until := in.clock.now().Add(48*time.Hour + 987654999*time.Nanosecond)
		if err := in.b.Admin().BlockUser(ctx, nina.ID, "spam wave", until); err != nil {
			t.Fatalf("BlockUser failed: %v", err)
		}
		if in.can(t, in.a, cookie) || in.can(t, in.b, cookie) || in.can(t, in.a, token) || in.can(t, in.b, token) {
			t.Fatal("a session of a blocked user works at the next request")
		}
		if _, err := in.a.Refresh(ctx, token.Tokens.RefreshToken); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Refresh of a blocked user = %v, want ErrUnauthenticated", err)
		}
		if _, err := in.a.Login(ctx, Credentials{Login: "nina@example.com", Password: goodPassword, IP: testIP, Kind: SessionCookie}); !errors.Is(err, ErrUserBlocked) {
			t.Fatalf("Login of a blocked user = %v, want ErrUserBlocked", err)
		}
		card, err := in.a.Admin().User(ctx, nina.ID)
		if err != nil || card.Status != StatusBlocked || card.BlockedReason != "spam wave" || !card.BlockedUntil.Equal(until.Truncate(time.Microsecond)) {
			t.Fatalf("the card is %+v, %v", card, err)
		}
		sessions, err := in.a.Admin().UserSessions(ctx, nina.ID)
		if err != nil || len(sessions) != 0 {
			t.Fatalf("the sessions of a blocked user are %+v, %v", sessions, err)
		}
		if err = in.a.Admin().UnblockUser(ctx, nina.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = in.b.Login(ctx, Credentials{Login: "nina@example.com", Password: goodPassword, IP: testIP, Kind: SessionCookie}); err != nil {
			t.Fatalf("Login after the block was lifted failed: %v", err)
		}
		page, err := in.b.Admin().ListAudit(ctx, AuditFilter{UserID: nina.ID, Actions: []string{"user.blocked", "user.unblocked"}})
		if err != nil || len(page.Entries) != 2 || page.Entries[0].Action != "user.unblocked" || page.Entries[1].Details["reason"] != "spam wave" {
			t.Fatalf("the audit log holds %+v, %v", page.Entries, err)
		}
	})
}

func TestADeletedUserIsKeptAndRestoredAcrossInstancesOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		olga := in.user(t, in.a, "olga")
		login := in.signIn(t, in.a, "olga", SessionCookie)
		if err := in.b.Admin().DeleteUser(ctx, olga.ID); err != nil {
			t.Fatalf("DeleteUser failed: %v", err)
		}
		if in.can(t, in.a, login) {
			t.Fatal("a session of a deleted user works")
		}
		if _, err := in.a.Login(ctx, Credentials{Login: "olga@example.com", Password: goodPassword, IP: testIP, Kind: SessionCookie}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login of a deleted user = %v, want ErrInvalidCredentials", err)
		}
		if _, err := in.a.Register(ctx, Registration{Identifiers: map[string]string{"email": "olga@example.com"}, Password: goodPassword}); !errors.Is(err, ErrIdentifierTaken) {
			t.Fatalf("Register with the address of a deleted user = %v, want ErrIdentifierTaken", err)
		}
		card, err := in.a.Admin().User(ctx, olga.ID)
		if err != nil || card.Status != StatusDeleted || !card.PurgeAfter.Equal(in.clock.now().Add(30*24*time.Hour).Truncate(time.Microsecond)) {
			t.Fatalf("the card is %+v, %v", card, err)
		}
		in.clock.advance(10 * 24 * time.Hour)
		if err = in.a.Admin().RestoreUser(ctx, olga.ID); err != nil {
			t.Fatalf("RestoreUser failed: %v", err)
		}
		if _, err = in.b.Login(ctx, Credentials{Login: "olga@example.com", Password: goodPassword, IP: testIP, Kind: SessionCookie}); err != nil {
			t.Fatalf("Login after the restoring failed: %v", err)
		}
	})
}

func TestAnImmediateDeletionFreesTheValuesOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstancesWith(t, d, WithImmediateDeletion())
		ctx := t.Context()
		pavel := in.user(t, in.a, "pavel")
		in.signIn(t, in.a, "pavel", SessionToken)
		if err := in.b.Admin().DeleteUser(ctx, pavel.ID); err != nil {
			t.Fatalf("DeleteUser failed: %v", err)
		}
		if _, err := in.a.Admin().User(ctx, pavel.ID); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("User = %v, want ErrUserNotFound", err)
		}
		if _, err := in.a.Register(ctx, Registration{Identifiers: map[string]string{"email": "pavel@example.com", "username": "pavel_n"}, Password: goodPassword}); err != nil {
			t.Fatalf("Register with the values of an erased user failed: %v", err)
		}
		records, err := in.a.Admin().ListAudit(ctx, AuditFilter{UserID: pavel.ID, Actions: []string{"user.deleted"}})
		if err != nil || len(records.Entries) != 1 || records.Entries[0].Details["mode"] != "immediate" {
			t.Fatalf("the audit log holds %+v, %v: it outlives the user", records.Entries, err)
		}
	})
}

func TestInstancesRemoveEachDeletedUserOnceOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		const count = 24
		var ids []UserID
		for n := range count {
			u := in.user(t, in.a, fmt.Sprintf("gone%02d", n))
			ids = append(ids, u.ID)
			if err := in.a.Admin().DeleteUser(ctx, u.ID); err != nil {
				t.Fatal(err)
			}
		}
		keep := in.user(t, in.a, "keeper")
		in.clock.advance(31 * 24 * time.Hour)
		var wg sync.WaitGroup
		for _, a := range []*Auth{in.a, in.b, in.a, in.b} {
			wg.Go(func() {
				if err := a.Cleanup(ctx); err != nil {
					t.Errorf("Cleanup failed: %v", err)
				}
			})
		}
		wg.Wait()
		page, err := in.a.Admin().ListAudit(ctx, AuditFilter{Actions: []string{"user.purged"}, Limit: 200})
		if err != nil {
			t.Fatal(err)
		}
		seen := map[UserID]int{}
		for _, e := range page.Entries {
			seen[e.UserID]++
			if e.ActorKind != "system" || e.ActorID != "maintenance" || e.Details["reason"] != "retention" {
				t.Fatalf("the removal is recorded as %+v", e)
			}
		}
		if len(page.Entries) != count || len(seen) != count {
			t.Fatalf("%d removals were recorded for %d users, want %d of each: one removal, one record", len(page.Entries), len(seen), count)
		}
		for _, id := range ids {
			if _, userErr := in.b.Admin().User(ctx, id); !errors.Is(userErr, ErrUserNotFound) {
				t.Fatalf("a user whose retention ended is still there: %v", userErr)
			}
		}
		if _, err = in.b.Admin().User(ctx, keep.ID); err != nil {
			t.Fatalf("a user who was not deleted was removed: %v", err)
		}
		if _, err = in.a.Register(ctx, Registration{Identifiers: map[string]string{"email": "gone00@example.com", "username": "gone00_n"}, Password: goodPassword}); err != nil {
			t.Fatalf("Register with the values of a removed user failed: %v", err)
		}
	})
}

func TestTheMaintenanceRemovesWhatHasRunOutOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstancesWith(t, d, WithSignup(), WithoutVerificationRequired(), WithAuditRetention(48*time.Hour))
		ctx := t.Context()
		for _, name := range []string{"visitor1", "visitor2"} {
			err := in.a.Signup(ctx, SignupRequest{Registration: Registration{
				Identifiers: map[string]string{"email": name + "@example.com", "username": name + "_n"}, Password: goodPassword,
			}})
			if err != nil {
				t.Fatal(err)
			}
		}
		confirmed := in.user(t, in.a, "regular")
		limited := in.user(t, in.a, "limited")
		if err := in.a.Admin().BlockUser(ctx, limited.ID, "reason", in.clock.now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		old := in.clock.now().Add(-72 * time.Hour)
		const oldRecords = 1130
		for n := range oldRecords {
			r := auditRecordAt(n, old.Add(-time.Duration(n)*time.Second))
			if err := in.a.store.Audit().Add(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		in.clock.advance(8 * 24 * time.Hour)
		if err := in.b.Cleanup(ctx); err != nil {
			t.Fatalf("Cleanup failed: %v", err)
		}
		page, err := in.a.Admin().ListUsers(ctx, UserFilter{})
		if err != nil {
			t.Fatal(err)
		}
		var logins []string
		for _, u := range page.Users {
			logins = append(logins, u.Identifiers[0].Value)
		}
		slices.Sort(logins)
		if !slices.Equal(logins, []string{"limited@example.com", "regular@example.com"}) {
			t.Fatalf("the users that are left are %v, want the two that signed up by themselves and were not visitors", logins)
		}
		if got := limited.ID; got == "" || confirmed.ID == "" {
			t.Fatal("the users were not made")
		}
		card, err := in.a.Admin().User(ctx, limited.ID)
		if err != nil || card.Status != StatusActive || card.BlockedReason != "" {
			t.Fatalf("the user whose block ran out is %+v, %v", card, err)
		}
		left, err := in.a.Admin().ListAudit(ctx, AuditFilter{Actions: []string{"test.action"}, Limit: 200})
		if err != nil || len(left.Entries) != 0 {
			t.Fatalf("%d old records of the audit log are left: %v", len(left.Entries), err)
		}
		purged, err := in.a.Admin().ListAudit(ctx, AuditFilter{Actions: []string{"user.purged"}})
		if err != nil || len(purged.Entries) != 2 || purged.Entries[0].Details["reason"] != "unconfirmed" {
			t.Fatalf("the removals of unconfirmed accounts are %+v, %v", purged.Entries, err)
		}
	})
}

func TestAListOfUsersIsSearchedSortedAndPagedOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		start := in.clock.now()
		type spec struct{ name, email, username string }
		specs := []spec{
			{"ann", "ann@example.com", "ann_a"}, {"bob", "bob@example.com", "bob_b"}, {"cara", "cara@example.org", "cara_c"},
			{"dan", "dan@example.com", "dan_d"}, {"eve", "eve@example.com", "eve_e"}, {"fifty", "fifty@example.com", "50_off"},
			{"fiftyx", "fiftyx@example.com", "50xoff"}, {"gus", "gus@example.com", "g%s_g"},
		}
		ids := map[string]UserID{}
		for _, s := range specs[:7] {
			u := mustRegister(t, in.a, map[string]string{"email": s.email, "username": s.username}, goodPassword)
			ids[s.name] = u.ID
			in.clock.advance(time.Hour)
		}
		login := func(name string, hours int) {
			u, err := in.a.store.Users().Get(ctx, in.a.tenant, string(ids[name]))
			if err != nil {
				t.Fatal(err)
			}
			u.LastLoginAt = start.Add(time.Duration(hours) * time.Hour)
			if _, err = in.a.store.Users().Update(ctx, u); err != nil {
				t.Fatal(err)
			}
		}
		login("bob", 30)
		login("eve", 20)
		names := func(page UserPage) []string {
			var got []string
			for _, u := range page.Users {
				for name, id := range ids {
					if id == u.ID {
						got = append(got, name)
					}
				}
			}
			return got
		}
		check := func(name string, filter UserFilter, want ...string) {
			t.Helper()
			page, err := in.b.Admin().ListUsers(ctx, filter)
			if err != nil {
				t.Fatalf("%s: ListUsers failed: %v", name, err)
			}
			if got := names(page); !slices.Equal(got, want) {
				t.Errorf("%s: the users are %v, want %v", name, got, want)
			}
		}
		check("oldest first", UserFilter{}, "ann", "bob", "cara", "dan", "eve", "fifty", "fiftyx")
		check("newest first", UserFilter{Descending: true, Limit: 3}, "fiftyx", "fifty", "eve")
		check("an address by its start", UserFilter{Search: "BOB@"}, "bob")
		check("an underscore is no wildcard", UserFilter{Search: "50_"}, "fifty")
		check("a percent sign is no wildcard", UserFilter{Search: "g%s"})
		check("only percent signs", UserFilter{Search: "%%%"})
		check("the start of many", UserFilter{Search: "fifty"}, "fifty", "fiftyx")
		check("by the last sign-in, never last", UserFilter{Order: UserOrderLastLogin}, "eve", "bob", "ann", "cara", "dan", "fifty", "fiftyx")
		check("by the last sign-in, downwards", UserFilter{Order: UserOrderLastLogin, Descending: true}, "bob", "eve", "fiftyx", "fifty", "dan", "cara", "ann")
		check("signed in in a period", UserFilter{LastLoginFrom: start.Add(10 * time.Hour), LastLoginBefore: start.Add(25 * time.Hour)}, "eve")
		check("never signed in", UserFilter{NeverLoggedIn: true}, "ann", "cara", "dan", "fifty", "fiftyx")
		check("made in a period", UserFilter{CreatedFrom: start.Add(time.Hour), CreatedBefore: start.Add(3 * time.Hour)}, "bob", "cara")
		for _, order := range []UserOrder{UserOrderCreated, UserOrderLastLogin, UserOrderStatus} {
			for _, descending := range []bool{false, true} {
				whole, err := in.a.Admin().ListUsers(ctx, UserFilter{Order: order, Descending: descending})
				if err != nil {
					t.Fatal(err)
				}
				var paged []string
				cursor := ""
				for range 10 {
					page, pageErr := in.b.Admin().ListUsers(ctx, UserFilter{Order: order, Descending: descending, Limit: 3, Cursor: cursor})
					if pageErr != nil {
						t.Fatalf("%s/%v: ListUsers failed: %v", order, descending, pageErr)
					}
					paged = append(paged, names(page)...)
					if cursor = page.Next; cursor == "" {
						break
					}
				}
				if !slices.Equal(paged, names(whole)) {
					t.Errorf("%s/%v: the pages hold %v, the whole list is %v", order, descending, paged, names(whole))
				}
			}
		}
		if page, err := in.a.Admin().ListUsers(ctx, UserFilter{Search: specs[7].username}); err != nil || len(page.Users) != 0 {
			t.Errorf("searching for a value that no user has finds %d users, %v", len(page.Users), err)
		}
	})
}

func TestTheAuditLogIsReadPageByPageThroughRecordsOfOneMomentOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		nina := in.user(t, in.a, "nina")
		const count = 25
		for n := range count {
			r := auditRecordAt(n, in.clock.now())
			r.TargetUserID = string(nina.ID)
			if err := in.a.store.Audit().Add(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		whole, err := in.a.Admin().ListAudit(ctx, AuditFilter{UserID: nina.ID, Actions: []string{"test.action"}, Limit: 200})
		if err != nil || len(whole.Entries) != count {
			t.Fatalf("ListAudit = %d entries, %v, want %d", len(whole.Entries), err, count)
		}
		var paged []string
		cursor := ""
		for range count {
			page, pageErr := in.b.Admin().ListAudit(ctx, AuditFilter{UserID: nina.ID, Actions: []string{"test.action"}, Limit: 4, Cursor: cursor})
			if pageErr != nil {
				t.Fatal(pageErr)
			}
			for _, e := range page.Entries {
				paged = append(paged, e.ID)
			}
			if cursor = page.Next; cursor == "" {
				break
			}
		}
		var wholeIDs []string
		for _, e := range whole.Entries {
			wholeIDs = append(wholeIDs, e.ID)
		}
		if !slices.Equal(paged, wholeIDs) {
			t.Fatalf("the pages hold %v, the whole log is %v", paged, wholeIDs)
		}
		if !slices.IsSortedFunc(wholeIDs, func(a, b string) int { return strings.Compare(b, a) }) {
			t.Fatalf("the records of one moment are not ordered by their ID, newest first: %v", wholeIDs)
		}
	})
}

func TestTheSettingOfOneInstanceReachesTheOtherOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		if needed, err := in.b.Admin().PasswordToEndSessions(ctx); err != nil || needed {
			t.Fatalf("the password is needed by default: %v, %v", needed, err)
		}
		if err := in.a.Admin().SetPasswordToEndSessions(ctx, true); err != nil {
			t.Fatal(err)
		}
		if needed, err := in.a.Admin().PasswordToEndSessions(ctx); err != nil || !needed {
			t.Fatalf("the instance that made the change does not see it: %v, %v", needed, err)
		}
		if needed, _ := in.b.Admin().PasswordToEndSessions(ctx); needed {
			t.Fatal("the other instance saw the change before its cache expired")
		}
		in.clock.advance(15 * time.Second)
		if needed, err := in.b.Admin().PasswordToEndSessions(ctx); err != nil || !needed {
			t.Fatalf("the other instance does not see the change after the cache expired: %v, %v", needed, err)
		}
		page, err := in.b.Admin().ListAudit(ctx, AuditFilter{Actions: []string{"setting.changed"}})
		if err != nil || len(page.Entries) != 1 || page.Entries[0].Details["new"] != "true" {
			t.Fatalf("the audit log holds %+v, %v", page.Entries, err)
		}
	})
}

func TestAnInvitationLinkWorksOnceWhenInstancesUseItAtTheSameTimeOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		sender := &recordingSender{}
		in := newInstancesWith(t, d, WithSender(sender), WithResetURL("https://app.example.com/reset"))
		ctx := t.Context()
		invited, err := in.a.Admin().InviteUser(ctx, Invitation{Identifiers: map[string]string{"email": "ivan@example.com"}, Language: "en"})
		if err != nil {
			t.Fatalf("InviteUser failed: %v", err)
		}
		eventually(t, "the invitation to be sent", func() bool { return len(sender.sent()) == 1 })
		link := sender.sent()[0].Link
		const racers = 6
		var accepted, refused atomic.Int32
		var winner atomic.Value
		var wg sync.WaitGroup
		start := make(chan struct{})
		for n := range racers {
			a := in.a
			if n%2 == 1 {
				a = in.b
			}
			wg.Go(func() {
				<-start
				chosen := fmt.Sprintf("the password that racer %d chose 123", n)
				resetErr := a.ResetPassword(ctx, ResetPasswordRequest{Token: tokenOf(link), Password: chosen})
				switch {
				case resetErr == nil:
					winner.Store(chosen)
					accepted.Add(1)
				case errors.Is(resetErr, ErrInvalidSecret):
					refused.Add(1)
				default:
					t.Errorf("racer %d: unexpected error %v", n, resetErr)
				}
			})
		}
		close(start)
		wg.Wait()
		if accepted.Load() != 1 || refused.Load() != racers-1 {
			t.Fatalf("%d racers set the password and %d were refused, want exactly 1 and %d: a link works once", accepted.Load(), refused.Load(), racers-1)
		}
		card, err := in.b.Admin().User(ctx, invited.ID)
		if err != nil || card.Identifiers[0].VerifiedAt.IsZero() {
			t.Fatalf("the channel of the invitation is not confirmed: %+v, %v", card, err)
		}
		password, _ := winner.Load().(string)
		if _, err = in.a.Login(ctx, Credentials{Login: "ivan@example.com", Password: password, IP: testIP, Kind: SessionCookie}); err != nil {
			t.Fatalf("Login with the password that won failed: %v", err)
		}
	})
}

func TestTwoInstancesThatGiveTheSameAddressToTwoUsersGiveItToOneOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		one := in.user(t, in.a, "one")
		two := in.user(t, in.a, "two")
		const racers = 8
		var done, taken atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for n := range racers {
			admin, id := in.a.Admin(), one.ID
			if n%2 == 1 {
				admin, id = in.b.Admin(), two.ID
			}
			wg.Go(func() {
				<-start
				err := admin.SetUserIdentifier(ctx, id, "email", "shared@example.com")
				switch {
				case err == nil:
					done.Add(1)
				case errors.Is(err, ErrIdentifierTaken):
					taken.Add(1)
				default:
					t.Errorf("racer %d: unexpected error %v", n, err)
				}
			})
		}
		close(start)
		wg.Wait()
		if done.Load() < 1 {
			t.Fatalf("nobody got the address: %d done, %d refused", done.Load(), taken.Load())
		}
		holders := 0
		for name, u := range map[string]User{"one": one, "two": two} {
			card, err := in.a.Admin().User(ctx, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			var emails []string
			for _, i := range card.Identifiers {
				if i.Type == "email" {
					emails = append(emails, i.Value)
				}
			}
			switch {
			case len(emails) != 1:
				t.Fatalf("%s has the addresses %v, want exactly one: a change that failed has to leave the old address", name, emails)
			case emails[0] == "shared@example.com":
				holders++
			case emails[0] != name+"@example.com":
				t.Fatalf("%s has the address %q", name, emails[0])
			}
		}
		if holders != 1 {
			t.Fatalf("%d users have the address, want exactly one", holders)
		}
	})
}

func TestUsersOfTheAdministrationAreCreatedAndTheirPasswordsResetOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		created, err := in.a.Admin().CreateUser(ctx, NewUser{Identifiers: map[string]string{"email": "quentin@example.com", "username": "quentin_q"}, Password: goodPassword})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		if _, err = in.b.Admin().CreateUser(ctx, NewUser{Identifiers: map[string]string{"email": "QUENTIN@example.com"}, Password: goodPassword}); !errors.Is(err, ErrIdentifierTaken) {
			t.Fatalf("CreateUser with a taken address = %v, want ErrIdentifierTaken", err)
		}
		temporary, err := in.b.Admin().SetTemporaryPassword(ctx, created.ID, "")
		if err != nil {
			t.Fatalf("SetTemporaryPassword failed: %v", err)
		}
		login, err := in.a.Login(ctx, Credentials{Login: "quentin_q", Password: temporary, IP: testIP, Kind: SessionCookie})
		if err != nil || !login.Principal.MustChangePassword {
			t.Fatalf("Login with the temporary password = %+v, %v", login, err)
		}
		if _, err = in.b.ChangePassword(ctx, login.Principal, temporary, "a password that quentin chose 1"); err != nil {
			t.Fatalf("ChangePassword failed: %v", err)
		}
		records, err := in.a.Admin().ListAudit(ctx, AuditFilter{UserID: created.ID, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, e := range records.Entries {
			seen[e.Action] = true
			if strings.Contains(fmt.Sprint(e.Details), temporary) {
				t.Fatalf("the temporary password is in the audit log: %+v", e)
			}
		}
		for _, action := range []string{"user.created", "user.password_temporary", "auth.login", "auth.password_changed"} {
			if !seen[action] {
				t.Errorf("the audit log of the user has no record of %s", action)
			}
		}
	})
}

func TestMomentsAtTheEdgesOfTheSupportedYearsWorkOnEveryDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, d *database) {
		in := newInstances(t, d)
		ctx := t.Context()
		nina := in.user(t, in.a, "nina")
		first := time.Date(1, time.January, 1, 0, 0, 1, 0, time.UTC)
		last := time.Date(9999, time.December, 31, 23, 59, 59, 999999000, time.UTC)
		if err := in.a.Admin().BlockUser(ctx, nina.ID, "far away", last); err != nil {
			t.Fatalf("BlockUser until the last moment failed: %v", err)
		}
		card, err := in.b.Admin().User(ctx, nina.ID)
		if err != nil || card.Status != StatusBlocked || !card.BlockedUntil.Equal(last) {
			t.Fatalf("the card is %+v, %v", card, err)
		}
		page, err := in.b.Admin().ListUsers(ctx, UserFilter{CreatedFrom: first, CreatedBefore: last, LastLoginFrom: first, LastLoginBefore: last})
		if err != nil || len(page.Users) != 0 {
			t.Fatalf("ListUsers at the edges = %+v, %v; want nobody, as nobody has signed in", page.Users, err)
		}
		page, err = in.b.Admin().ListUsers(ctx, UserFilter{CreatedFrom: first, CreatedBefore: last})
		if err != nil || len(page.Users) != 1 {
			t.Fatalf("ListUsers created between the edges = %+v, %v; want the user", page.Users, err)
		}
		entries, err := in.b.Admin().ListAudit(ctx, AuditFilter{From: first, To: last, UserID: nina.ID})
		if err != nil || len(entries.Entries) == 0 {
			t.Fatalf("ListAudit between the edges = %+v, %v; want the records of the user", entries, err)
		}
		cursor := encodeAuditCursor(store.AuditRecord{At: time.UnixMicro(0), ID: "x"})
		if entries, err = in.b.Admin().ListAudit(ctx, AuditFilter{Cursor: cursor}); err != nil || len(entries.Entries) != 0 {
			t.Fatalf("ListAudit after the beginning of the epoch = %+v, %v; want nothing", entries.Entries, err)
		}
		cursor = encodeAuditCursor(store.AuditRecord{At: last, ID: "x"})
		if entries, err = in.b.Admin().ListAudit(ctx, AuditFilter{Cursor: cursor}); err != nil || len(entries.Entries) == 0 {
			t.Fatalf("ListAudit after the last moment = %+v, %v; want everything", entries.Entries, err)
		}
	})
}
