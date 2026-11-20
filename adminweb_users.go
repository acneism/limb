package limb

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/store"
)

var pageSizes = []int{10, 25, 50, 100, 200}

var usersFieldTexts = map[string]string{
	"limit": "users.limit", "order": "users.order", "statuses": "users.status", "created_via": "users.via", "created_from": "users.created.from",
	"created_before": "users.created.to", "last_login_from": "users.login.from", "last_login_before": "users.login.to",
	"cursor": "users.field.cursor", "search": "users.field.search",
}

type usersQuery struct {
	search                                     string
	statuses                                   []Status
	confirmed, via                             string
	createdFrom, createdTo, loginFrom, loginTo string
	never                                      bool
	order                                      UserOrder
	descending                                 bool
	limit                                      int
	cursor                                     string
	invalid                                    []string
}

func (q *usersQuery) reject(key string) {
	if !slices.Contains(q.invalid, key) {
		q.invalid = append(q.invalid, key)
	}
}

func validDay(text string) bool {
	at, err := time.Parse(time.DateOnly, text)
	return err == nil && at.Year() >= firstYear && at.Year() <= lastYear
}

func (q *usersQuery) day(values url.Values, name, key string) string {
	text := values.Get(name)
	if text == "" {
		return ""
	}
	if !validDay(text) {
		q.reject(key)
		return ""
	}
	return text
}

func parseUsersQuery(values url.Values) usersQuery {
	q := usersQuery{order: UserOrderCreated, descending: true, limit: defaultUsersPage, search: strings.TrimSpace(values.Get("q"))}
	for _, text := range values["status"] {
		switch status := Status(text); {
		case text == "":
		case !validStatus(status):
			q.reject("users.status")
		case !slices.Contains(q.statuses, status):
			q.statuses = append(q.statuses, status)
		}
	}
	switch q.confirmed = values.Get("confirmed"); q.confirmed {
	case "", "yes", "no":
	default:
		q.confirmed = ""
		q.reject("users.confirmed")
	}
	if q.via = values.Get("via"); q.via != "" && !validCreatedVia(store.CreatedVia(q.via)) {
		q.via = ""
		q.reject("users.via")
	}
	q.createdFrom = q.day(values, "created_from", "users.created.from")
	q.createdTo = q.day(values, "created_to", "users.created.to")
	q.loginFrom = q.day(values, "login_from", "users.login.from")
	q.loginTo = q.day(values, "login_to", "users.login.to")
	q.never = values.Get("never") != ""
	switch order := UserOrder(values.Get("order")); order {
	case "":
	case UserOrderCreated, UserOrderLastLogin, UserOrderStatus:
		q.order, q.descending = order, order != UserOrderStatus
	default:
		q.reject("users.order")
	}
	switch values.Get("dir") {
	case "":
	case "asc":
		q.descending = false
	case "desc":
		q.descending = true
	default:
		q.reject("users.dir")
	}
	if text := values.Get("limit"); text != "" {
		if n, err := strconv.Atoi(text); err == nil && slices.Contains(pageSizes, n) {
			q.limit = n
		} else {
			q.reject("users.limit")
		}
	}
	if q.cursor = values.Get("cursor"); len(q.cursor) > longestCursor {
		q.cursor = ""
		q.reject("users.field.cursor")
	}
	return q
}

func dayStart(text string) time.Time {
	at, err := time.Parse(time.DateOnly, text)
	if err != nil {
		return time.Time{}
	}
	return at
}

func dayAfter(text string) time.Time {
	at := dayStart(text)
	if at.IsZero() {
		return at
	}
	if next := at.AddDate(0, 0, 1); next.Year() <= lastYear {
		return next
	}
	return time.Time{}
}

func pointerTo(value bool) *bool {
	return &value
}

func (q usersQuery) filter() UserFilter {
	f := UserFilter{
		Statuses: q.statuses, CreatedVia: q.via, Search: q.search, NeverLoggedIn: q.never,
		Order: q.order, Descending: q.descending, Limit: q.limit, Cursor: q.cursor,
		CreatedFrom: dayStart(q.createdFrom), CreatedBefore: dayAfter(q.createdTo),
		LastLoginFrom: dayStart(q.loginFrom), LastLoginBefore: dayAfter(q.loginTo),
	}
	switch q.confirmed {
	case "yes":
		f.Confirmed = pointerTo(true)
	case "no":
		f.Confirmed = pointerTo(false)
	}
	return f
}

func (q usersQuery) filtered() bool {
	return q.search != "" || len(q.statuses) > 0 || q.confirmed != "" || q.via != "" || q.createdFrom != "" || q.createdTo != "" || q.loginFrom != "" || q.loginTo != "" || q.never
}

func directionText(descending bool) string {
	if descending {
		return "desc"
	}
	return "asc"
}

func (q usersQuery) values() url.Values {
	values := url.Values{}
	for name, text := range map[string]string{
		"q": q.search, "confirmed": q.confirmed, "via": q.via, "created_from": q.createdFrom, "created_to": q.createdTo,
		"login_from": q.loginFrom, "login_to": q.loginTo,
	} {
		if text != "" {
			values.Set(name, text)
		}
	}
	for _, status := range q.statuses {
		values.Add("status", string(status))
	}
	if q.never {
		values.Set("never", "1")
	}
	values.Set("order", string(q.order))
	values.Set("dir", directionText(q.descending))
	values.Set("limit", strconv.Itoa(q.limit))
	if q.cursor != "" {
		values.Set("cursor", q.cursor)
	}
	return values
}

func (c *adminCall) usersLink(q usersQuery) string {
	return c.s.base + "/users?" + q.values().Encode()
}

func options(p *adminui.Page, selected string, entries [][2]string) []adminui.Option {
	list := make([]adminui.Option, 0, len(entries))
	for _, entry := range entries {
		list = append(list, adminui.Option{Value: entry[0], Label: p.T(entry[1]), Selected: entry[0] == selected})
	}
	return list
}

func (c *adminCall) usersForm(p *adminui.Page, q usersQuery) adminui.UsersForm {
	form := adminui.UsersForm{
		Search: q.search, CreatedFrom: q.createdFrom, CreatedTo: q.createdTo, LoginFrom: q.loginFrom, LoginTo: q.loginTo, Never: q.never,
		Confirmed: options(p, q.confirmed, [][2]string{{"", "users.confirmed.any"}, {"yes", "users.confirmed.yes"}, {"no", "users.confirmed.no"}}),
		Via: options(p, q.via, [][2]string{
			{"", "users.via.any"}, {string(store.CreatedViaAPI), "via.api"}, {string(store.CreatedViaSignup), "via.signup"},
			{string(store.CreatedViaAdmin), "via.admin"}, {string(store.CreatedViaInvite), "via.invite"},
		}),
		Order: options(p, string(q.order), [][2]string{
			{string(UserOrderCreated), "users.order.created"}, {string(UserOrderLastLogin), "users.order.last"}, {string(UserOrderStatus), "users.order.status"},
		}),
		Direction: options(p, directionText(q.descending), [][2]string{{"asc", "users.dir.asc"}, {"desc", "users.dir.desc"}}),
	}
	for _, status := range []Status{store.StatusActive, store.StatusBlocked, store.StatusDeleted} {
		form.Statuses = append(form.Statuses, adminui.Choice{
			Name: "status", Value: string(status), Label: p.T("status." + string(status)), Checked: slices.Contains(q.statuses, status),
		})
	}
	for _, n := range pageSizes {
		form.Limit = append(form.Limit, adminui.Option{Value: strconv.Itoa(n), Label: strconv.Itoa(n), Selected: n == q.limit})
	}
	return form
}

func (c *adminCall) sortLink(q usersQuery, order UserOrder) adminui.SortLink {
	next := q
	next.order, next.cursor = order, ""
	state := "none"
	if q.order == order {
		state = "ascending"
		if q.descending {
			state = "descending"
		}
		next.descending = !q.descending
	} else {
		next.descending = order != UserOrderStatus
	}
	return adminui.SortLink{Href: c.usersLink(next), State: state}
}

func viaText(p *adminui.Page, via string) string {
	switch store.CreatedVia(via) {
	case store.CreatedViaAPI, store.CreatedViaSignup, store.CreatedViaAdmin, store.CreatedViaInvite:
		return p.T("via." + via)
	}
	return via
}

func identifierViews(user ManagedUser) []adminui.IdentifierView {
	views := make([]adminui.IdentifierView, 0, len(user.Identifiers))
	for _, i := range user.Identifiers {
		views = append(views, adminui.IdentifierView{Type: i.Type, Value: shownValue(i), Verified: !i.VerifiedAt.IsZero()})
	}
	return views
}

func (c *adminCall) userRow(p *adminui.Page, u ManagedUser) adminui.UserRow {
	row := adminui.UserRow{
		Href: c.s.base + "/users/" + string(u.ID), Title: titleOf(u), Identifiers: identifierViews(u), Status: string(u.Status),
		StatusLabel: p.T("status." + string(u.Status)), CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt, Via: viaText(p, u.CreatedVia),
		MustChangePassword: u.MustChangePassword,
	}
	if u.Status == store.StatusBlocked {
		row.BlockedUntil = u.BlockedUntil
	}
	return row
}

func (c *adminCall) showUsers() {
	ses, ok := c.requireSession()
	if !ok {
		return
	}
	q := parseUsersQuery(c.r.URL.Query())
	p := c.signedPage(ses)
	p.Title = p.T("users.title")
	if q.invalid == nil && c.r.URL.Query().Get("done") == "erased" {
		p.Flash, p.FlashKind = p.T("users.notice.erased"), "notice"
	}
	data := adminui.UsersData{Form: c.usersForm(p, q), Filtered: q.filtered()}
	status := http.StatusOK
	var labels []string
	for _, key := range q.invalid {
		labels = append(labels, p.T(key))
	}
	if len(labels) == 0 {
		page, err := c.auth().listUsers(c.ctx(), q.filter())
		var invalid *ValidationError
		switch {
		case errors.As(err, &invalid):
			labels = append(labels, fieldLabel(p, usersFieldTexts, invalid.Field))
		case err != nil:
			c.internal(err)
			return
		default:
			for _, user := range page.Users {
				data.Rows = append(data.Rows, c.userRow(p, user))
			}
			if page.Next != "" {
				next := q
				next.cursor = page.Next
				data.Next = c.usersLink(next)
			}
			if q.cursor != "" {
				first := q
				first.cursor = ""
				data.First = c.usersLink(first)
			}
		}
	}
	if len(labels) > 0 {
		status = http.StatusBadRequest
		p.Flash, p.FlashKind = p.T("users.invalid", strings.Join(labels, ", ")), "error"
	}
	data.ByCreated, data.ByLastLogin, data.ByStatus = c.sortLink(q, UserOrderCreated), c.sortLink(q, UserOrderLastLogin), c.sortLink(q, UserOrderStatus)
	p.Data = data
	c.render(status, "users", p)
}

func fieldLabel(p *adminui.Page, texts map[string]string, field string) string {
	if key, known := texts[field]; known {
		return p.T(key)
	}
	return field
}
