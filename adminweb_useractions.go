package limb

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/store"
)

func parseBlockDay(text string) (time.Time, bool) {
	if text == "" {
		return time.Time{}, true
	}
	at, err := time.Parse(time.DateOnly, text)
	if err != nil || at.IsZero() || at.Year() < firstYear || at.Year() > lastYear {
		return time.Time{}, false
	}
	return at, true
}

func (a *Auth) deletionConfirmed(u ManagedUser, text string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	if len(u.Identifiers) == 0 {
		return text == string(u.ID)
	}
	for _, i := range u.Identifiers {
		if text == i.Value || text == i.DisplayValue {
			return true
		}
		for _, kind := range a.types {
			if value, err := kind.Normalize(text); kind.Name() == i.Type && err == nil && value == i.Value {
				return true
			}
		}
	}
	return false
}

func validationAnswer(v *ValidationError) (int, func(p *adminui.Page) string) {
	switch {
	case v.Field == "reason" && v.Reason == "required":
		return http.StatusUnprocessableEntity, textOf("user.error.reason.required")
	case v.Field == "reason":
		return http.StatusUnprocessableEntity, func(p *adminui.Page) string { return p.T("user.error.reason.invalid", store.MaxBlockedReasonLength) }
	case v.Field == "until" && v.Reason == "must be in the future":
		return http.StatusUnprocessableEntity, textOf("user.error.until.past")
	case v.Field == "until":
		return http.StatusUnprocessableEntity, textOf("user.error.until.invalid")
	case v.Field == "user" && v.Reason == "is not deleted":
		return http.StatusConflict, textOf("user.error.notdeleted")
	case v.Field == "identifiers" && v.Reason == "at least one value to sign in with is required":
		return http.StatusUnprocessableEntity, textOf("user.error.lastlogin")
	}
	return http.StatusUnprocessableEntity, func(p *adminui.Page) string { return p.T("user.error.identifier", v.Field, v.Reason) }
}

func (c *adminCall) userFailure(ses admin.Session, form url.Values, err error) {
	var invalid *ValidationError
	var policy *PolicyError
	var flash func(p *adminui.Page) string
	status := http.StatusConflict
	switch {
	case errors.Is(err, ErrUserNotFound):
		c.fail(http.StatusNotFound)
		return
	case errors.As(err, &invalid):
		status, flash = validationAnswer(invalid)
	case errors.Is(err, ErrUserDeleted):
		flash = textOf("user.error.deleted")
	case errors.Is(err, ErrConcurrentChange):
		flash = textOf("user.error.changed")
	case errors.Is(err, ErrDeletionRefused):
		flash = textOf("user.error.refused")
	case errors.Is(err, ErrRetentionOver):
		flash = textOf("user.error.retention")
	case errors.Is(err, ErrIdentifierTaken):
		flash = textOf("user.error.taken")
	case errors.Is(err, ErrRecoveryDisabled):
		flash = textOf("user.error.nosender")
	case errors.Is(err, ErrNoConfirmedChannel):
		flash = textOf("user.error.nochannel")
	case errors.Is(err, ErrBusy):
		status, flash = http.StatusServiceUnavailable, textOf("user.error.busy")
		c.w.Header().Set("Retry-After", busyRetryAfter)
	case errors.As(err, &policy):
		status, flash = http.StatusUnprocessableEntity, textOf("user.error.temporary")
	default:
		c.internal(err)
		return
	}
	c.userPage(ses, status, flash, form)
}

func (c *adminCall) userResult(ses admin.Session, form url.Values, err error, notice string) {
	if err != nil {
		c.userFailure(ses, form, err)
		return
	}
	c.redirect("/users/" + c.userID + "?done=" + notice)
}

func (c *adminCall) submitBlock() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	until, valid := parseBlockDay(form.Get("until"))
	if !valid {
		c.userFailure(ses, form, &ValidationError{Field: "until", Reason: "is not a day"})
		return
	}
	c.userResult(ses, form, c.auth().blockUser(c.ctx(), c.by(ses), UserID(c.userID), form.Get("reason"), until), "blocked")
}

func (c *adminCall) submitUnblock() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	c.userResult(ses, form, c.auth().unblockUser(c.ctx(), c.by(ses), UserID(c.userID)), "unblocked")
}

func (c *adminCall) submitEndSession() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	var err error
	if sessionID := form.Get("session"); sessionID != "" && len(sessionID) <= store.MaxIDLength {
		err = c.auth().endUserSession(c.ctx(), c.by(ses), UserID(c.userID), sessionID)
	}
	if errors.Is(err, ErrSessionNotFound) {
		err = nil
	}
	c.userResult(ses, form, err, "session")
}

func (c *adminCall) submitEndSessions() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	_, err := c.auth().endUserSessions(c.ctx(), c.by(ses), UserID(c.userID))
	c.userResult(ses, form, err, "sessions")
}

func (c *adminCall) submitDelete() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	a := c.auth()
	user, err := a.managedUserByID(c.ctx(), UserID(c.userID))
	if err != nil {
		c.userFailure(ses, form, err)
		return
	}
	if !a.deletionConfirmed(user, form.Get("confirm")) {
		c.userPage(ses, http.StatusUnprocessableEntity, textOf("user.error.confirm"), form)
		return
	}
	switch err = a.deleteUser(c.ctx(), c.by(ses), user.ID); {
	case err != nil:
		c.userFailure(ses, form, err)
	case a.immediate:
		c.redirect("/users?done=erased")
	default:
		c.redirect("/users/" + c.userID + "?done=deleted")
	}
}

func (c *adminCall) submitRestore() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	c.userResult(ses, form, c.auth().restoreUser(c.ctx(), c.by(ses), UserID(c.userID)), "restored")
}
