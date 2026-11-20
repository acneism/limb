package limb

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/acneism/limb/internal/adminui"
)

var auditFieldTexts = map[string]string{
	"limit": "users.limit", "actions": "audit.f.action", "from": "audit.f.from", "to": "audit.f.to", "cursor": "users.field.cursor",
}

type auditQuery struct {
	user, admin, action string
	from, to            string
	limit               int
	cursor              string
	invalid             []string
}

func (q *auditQuery) reject(key string) {
	if !slices.Contains(q.invalid, key) {
		q.invalid = append(q.invalid, key)
	}
}

func (q *auditQuery) identifier(values url.Values, name, key string) string {
	text := strings.TrimSpace(values.Get(name))
	if text != "" && !validPathID(text) {
		q.reject(key)
		return ""
	}
	return text
}

func (q *auditQuery) day(values url.Values, name, key string) string {
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

func parseAuditQuery(values url.Values) auditQuery {
	q := auditQuery{limit: defaultAuditPage}
	q.user = q.identifier(values, "user", "audit.f.user")
	q.admin = q.identifier(values, "admin", "audit.f.admin")
	if q.action = values.Get("action"); q.action != "" && !slices.Contains(auditActions, q.action) {
		q.action = ""
		q.reject("audit.f.action")
	}
	q.from = q.day(values, "from", "audit.f.from")
	q.to = q.day(values, "to", "audit.f.to")
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

func (q auditQuery) filter() AuditFilter {
	f := AuditFilter{
		UserID: UserID(q.user), AdminID: q.admin, From: dayStart(q.from), To: dayAfter(q.to), Cursor: q.cursor, Limit: q.limit,
	}
	if q.action != "" {
		f.Actions = []string{q.action}
	}
	return f
}

func (q auditQuery) filtered() bool {
	return q.user != "" || q.admin != "" || q.action != "" || q.from != "" || q.to != ""
}

func (q auditQuery) values() url.Values {
	values := url.Values{}
	for name, text := range map[string]string{"user": q.user, "admin": q.admin, "action": q.action, "from": q.from, "to": q.to, "cursor": q.cursor} {
		if text != "" {
			values.Set(name, text)
		}
	}
	values.Set("limit", strconv.Itoa(q.limit))
	return values
}

func (c *adminCall) auditLink(q auditQuery) string {
	return c.s.base + "/audit?" + q.values().Encode()
}

func (c *adminCall) auditForm(p *adminui.Page, q auditQuery) (adminui.AuditForm, error) {
	admins, err := c.auth().store.Admins().List(c.ctx(), c.auth().tenant)
	if err != nil {
		return adminui.AuditForm{}, err
	}
	form := adminui.AuditForm{User: q.user, From: q.from, To: q.to}
	form.Admins = append(form.Admins, adminui.Option{Value: "", Label: p.T("audit.f.admin.any"), Selected: q.admin == ""})
	known := false
	for _, a := range admins {
		known = known || a.ID == q.admin
		form.Admins = append(form.Admins, adminui.Option{Value: a.ID, Label: a.Login, Selected: a.ID == q.admin})
	}
	if q.admin != "" && !known {
		form.Admins = append(form.Admins, adminui.Option{Value: q.admin, Label: p.T("audit.actor.admin.gone", shorten(q.admin)), Selected: true})
	}
	form.Actions = append(form.Actions, adminui.Option{Value: "", Label: p.T("audit.f.action.any"), Selected: q.action == ""})
	for _, action := range auditActions {
		form.Actions = append(form.Actions, adminui.Option{Value: action, Label: p.T("audit.action." + action), Selected: action == q.action})
	}
	for _, n := range pageSizes {
		form.Limit = append(form.Limit, adminui.Option{Value: strconv.Itoa(n), Label: strconv.Itoa(n), Selected: n == q.limit})
	}
	return form, nil
}

func (c *adminCall) showAudit() {
	ses, ok := c.requireSession()
	if !ok {
		return
	}
	q := parseAuditQuery(c.r.URL.Query())
	p := c.signedPage(ses)
	p.Title = p.T("audit.title")
	form, err := c.auditForm(p, q)
	if err != nil {
		c.internal(err)
		return
	}
	data := adminui.AuditData{Form: form, Filtered: q.filtered()}
	status := http.StatusOK
	var labels []string
	for _, key := range q.invalid {
		labels = append(labels, p.T(key))
	}
	if len(labels) == 0 {
		page, listErr := c.auth().listAudit(c.ctx(), q.filter())
		var invalid *ValidationError
		switch {
		case errors.As(listErr, &invalid):
			labels = append(labels, fieldLabel(p, auditFieldTexts, invalid.Field))
		case listErr != nil:
			c.internal(listErr)
			return
		default:
			if data.Rows, err = c.auditRows(p, page.Entries); err != nil {
				c.internal(err)
				return
			}
			if page.Next != "" {
				next := q
				next.cursor = page.Next
				data.Next = c.auditLink(next)
			}
			if q.cursor != "" {
				first := q
				first.cursor = ""
				data.First = c.auditLink(first)
			}
		}
	}
	if len(labels) > 0 {
		status = http.StatusBadRequest
		p.Flash, p.FlashKind = p.T("users.invalid", strings.Join(labels, ", ")), "error"
	}
	p.Data = data
	c.render(status, "audit", p)
}
