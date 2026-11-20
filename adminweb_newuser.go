package limb

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/adminui"
)

func (c *adminCall) newUserPage(ses admin.Session, status int, form url.Values, flash func(p *adminui.Page) string) {
	a := c.auth()
	p := c.signedPage(ses)
	p.Title = p.T("newuser.title")
	data := adminui.NewUserData{Mode: "password", Keep: form.Get("keep") != "", CanInvite: a.invitationsReady(), Languages: messageLanguages(p)}
	if form.Get("mode") == "invite" && data.CanInvite {
		data.Mode = "invite"
	}
	for _, kind := range a.types {
		data.Fields = append(data.Fields, adminui.NewUserField{
			Type: kind.Name(), Value: form.Get("value." + kind.Name()), Required: kind.IsRequired(), Delivery: kind.IsDelivery(),
			Verified: form.Get("verified."+kind.Name()) != "",
		})
	}
	if language := form.Get("language"); language != "" {
		chosen := normalizeLanguage(language)
		for i := range data.Languages {
			data.Languages[i].Selected = data.Languages[i].Value == chosen
		}
	}
	if flash != nil {
		p.Flash, p.FlashKind = flash(p), "error"
	}
	p.Data = data
	c.render(status, "newuser", p)
}

func (c *adminCall) showNewUser() {
	ses, ok := c.requireSession()
	if !ok {
		return
	}
	c.newUserPage(ses, http.StatusOK, nil, nil)
}

func (c *adminCall) newUserFailure(ses admin.Session, form url.Values, err error) {
	var invalid *ValidationError
	var policy *PolicyError
	status := http.StatusConflict
	var flash func(p *adminui.Page) string
	switch {
	case errors.As(err, &invalid):
		status, flash = validationAnswer(invalid)
	case errors.As(err, &policy):
		status, flash = http.StatusUnprocessableEntity, func(p *adminui.Page) string { return ruleTexts(p, policy.Rules) }
	case errors.Is(err, ErrIdentifierTaken):
		flash = textOf("user.error.taken")
	case errors.Is(err, ErrInvitationsDisabled):
		flash = textOf("user.error.invitations")
	default:
		c.internal(err)
		return
	}
	c.newUserPage(ses, status, form, flash)
}

func (c *adminCall) newUserValues(form url.Values) (map[string]string, []string) {
	values := make(map[string]string, len(c.auth().types))
	var verified []string
	for _, kind := range c.auth().types {
		text := strings.TrimSpace(form.Get("value." + kind.Name()))
		if text == "" {
			continue
		}
		values[kind.Name()] = text
		if form.Get("verified."+kind.Name()) != "" {
			verified = append(verified, kind.Name())
		}
	}
	return values, verified
}

func (c *adminCall) submitNewUser() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	a := c.auth()
	values, verified := c.newUserValues(form)
	if form.Get("mode") == "invite" {
		created, err := a.inviteUser(c.ctx(), c.by(ses), Invitation{Identifiers: values, Language: form.Get("language")})
		switch {
		case err == nil:
			c.redirect("/users/" + string(created.ID) + "?done=invited")
		case errors.Is(err, ErrBusy) && created.ID != "":
			c.redirect("/users/" + string(created.ID) + "?done=invitebusy")
		default:
			c.newUserFailure(ses, form, err)
		}
		return
	}
	created, err := a.createUser(c.ctx(), c.by(ses), NewUser{Identifiers: values, Password: form.Get("password"), KeepPassword: form.Get("keep") != "", Verified: verified})
	if err != nil {
		c.newUserFailure(ses, form, err)
		return
	}
	c.redirect("/users/" + string(created.ID) + "?done=created")
}

func (c *adminCall) submitInvitation() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	c.userResult(ses, form, c.auth().resendInvitation(c.ctx(), c.by(ses), UserID(c.userID), form.Get("language")), "invitation")
}
