package limb

import (
	"net/http"
)

const busyRetryAfter = "5"

type signupBody struct {
	Identifiers map[string]string `json:"identifiers"`
	Password    string            `json:"password"`
	Extra       map[string]string `json:"extra"`
}

type signupAnswer struct {
	VerificationRequired bool `json:"verification_required"`
}

type accountBody struct {
	Login string `json:"login"`
}

type confirmBody struct {
	Token   string `json:"token"`
	Login   string `json:"login"`
	Channel string `json:"channel"`
	Code    string `json:"code"`
}

type resetBody struct {
	confirmBody
	Password string `json:"password"`
}

func (a *Auth) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body signupBody
	if e := readJSON(w, r, &body, true); e != nil {
		writeError(w, r, e)
		return
	}
	err := a.Signup(r.Context(), SignupRequest{
		Registration: Registration{Identifiers: body.Identifiers, Password: body.Password, Extra: body.Extra},
		IP:           a.clientIP(r),
		Language:     negotiateLanguage(r.Header.Get("Accept-Language")),
	})
	if err != nil {
		a.failValues(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, signupAnswer{VerificationRequired: a.needVerified})
}

func (a *Auth) readLogin(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body accountBody
	if e := readJSON(w, r, &body, true); e != nil {
		writeError(w, r, e)
		return "", false
	}
	return body.Login, true
}

func (a *Auth) handleVerificationRequest(w http.ResponseWriter, r *http.Request) {
	login, ok := a.readLogin(w, r)
	if !ok {
		return
	}
	err := a.RequestVerification(r.Context(), VerificationRequest{
		Login: login, IP: a.clientIP(r), Language: negotiateLanguage(r.Header.Get("Accept-Language")),
	})
	if err != nil {
		a.failValues(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (a *Auth) handleResetRequest(w http.ResponseWriter, r *http.Request) {
	login, ok := a.readLogin(w, r)
	if !ok {
		return
	}
	err := a.RequestPasswordReset(r.Context(), ResetRequest{
		Login: login, IP: a.clientIP(r), Language: negotiateLanguage(r.Header.Get("Accept-Language")),
	})
	if err != nil {
		a.failValues(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (a *Auth) handleVerify(w http.ResponseWriter, r *http.Request) {
	var body confirmBody
	if e := readJSON(w, r, &body, true); e != nil {
		writeError(w, r, e)
		return
	}
	err := a.Verify(r.Context(), VerifyRequest{
		Token: body.Token, Login: body.Login, Channel: body.Channel, Code: body.Code, IP: a.clientIP(r),
	})
	if err != nil {
		a.failValues(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) handleReset(w http.ResponseWriter, r *http.Request) {
	var body resetBody
	if e := readJSON(w, r, &body, true); e != nil {
		writeError(w, r, e)
		return
	}
	err := a.ResetPassword(r.Context(), ResetPasswordRequest{
		Token: body.Token, Login: body.Login, Channel: body.Channel, Code: body.Code, Password: body.Password,
		IP: a.clientIP(r), Language: negotiateLanguage(r.Header.Get("Accept-Language")),
	})
	if err != nil {
		a.failValues(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
