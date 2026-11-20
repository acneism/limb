package limb

import (
	"net/url"

	"github.com/acneism/limb/internal/admin"
)

func (c *adminCall) identifierEdit(ses admin.Session, form url.Values, notice string, edit func(by actorRef, id UserID, typ string) error) {
	typ := form.Get("type")
	if _, declared := c.auth().known[typ]; !declared {
		c.userFailure(ses, form, &ValidationError{Field: "type", Reason: "unknown identifier type"})
		return
	}
	c.userResult(ses, form, edit(c.by(ses), UserID(c.userID), typ), notice)
}

func (c *adminCall) submitIdentifierSet() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	c.identifierEdit(ses, form, "value", func(by actorRef, id UserID, typ string) error {
		return c.auth().changeIdentifier(c.ctx(), by, id, typ, form.Get("value"))
	})
}

func (c *adminCall) submitIdentifierRemove() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	c.identifierEdit(ses, form, "removed", func(by actorRef, id UserID, typ string) error {
		return c.auth().removeIdentifier(c.ctx(), by, id, typ)
	})
}

func (c *adminCall) submitIdentifierVerify() {
	ses, form, ok := c.signedForm()
	if !ok {
		return
	}
	c.identifierEdit(ses, form, "confirmed", func(by actorRef, id UserID, typ string) error {
		return c.auth().verifyIdentifier(c.ctx(), by, id, typ)
	})
}
