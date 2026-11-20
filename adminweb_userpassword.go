package limb

import (
	"net/http"

	"github.com/acneism/limb/internal/adminui"
)

func (c *adminCall) submitResetLink() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	c.userResult(ses, form, c.auth().sendResetLink(c.ctx(), c.by(ses), UserID(c.userID), form.Get("language")), "link")
}

func (c *adminCall) submitTemporaryPassword() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	a := c.auth()
	password, err := a.setTemporaryPassword(c.ctx(), c.by(ses), UserID(c.userID), form.Get("language"))
	if err != nil {
		c.userFailure(ses, form, err)
		return
	}
	title := c.userID
	if user, lookupErr := a.managedUserByID(c.ctx(), UserID(c.userID)); lookupErr == nil {
		title = titleOf(user)
	}
	p := c.signedPage(ses)
	p.Title = p.T("temporary.title")
	p.Data = adminui.TemporaryData{UserHref: c.s.base + "/users/" + c.userID, Title: title, Password: password}
	c.render(http.StatusOK, "temporary", p)
}
