package limb

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxBodyBytes    = 64 << 10
	maxLanguageText = 1 << 10
	maxLanguages    = 32
	defaultLanguage = "en"
)

const (
	codeInvalidRequest         = "invalid_request"
	codeInvalidCredentials     = "invalid_credentials" //nolint:gosec
	codeUserBlocked            = "user_blocked"
	codeRateLimited            = "rate_limited"
	codePasswordChangeRequired = "password_change_required"
	codeUnauthenticated        = "unauthenticated"
	codeCSRFFailed             = "csrf_failed"
	codePolicyViolation        = "policy_violation"
	codeNotFound               = "not_found"
	codeMethodNotAllowed       = "method_not_allowed"
	codeUnsupportedMediaType   = "unsupported_media_type"
	codeInternal               = "internal_error"
	messageRequestTooLarge     = "request_too_large"
)

var statusOfCode = map[string]int{
	codeInvalidRequest:         http.StatusBadRequest,
	codeInvalidCredentials:     http.StatusUnauthorized,
	codeUserBlocked:            http.StatusForbidden,
	codeRateLimited:            http.StatusTooManyRequests,
	codePasswordChangeRequired: http.StatusForbidden,
	codeUnauthenticated:        http.StatusUnauthorized,
	codeCSRFFailed:             http.StatusForbidden,
	codePolicyViolation:        http.StatusUnprocessableEntity,
	codeNotFound:               http.StatusNotFound,
	codeMethodNotAllowed:       http.StatusMethodNotAllowed,
	codeUnsupportedMediaType:   http.StatusUnsupportedMediaType,
	codeInternal:               http.StatusInternalServerError,
}

var messages = map[string]map[string]string{
	"en": {
		codeInvalidRequest:         "The request is not valid.",
		codeInvalidCredentials:     "The login or the password is wrong.",
		codeUserBlocked:            "The account is blocked.",
		codeRateLimited:            "Too many attempts. Try again later.",
		codePasswordChangeRequired: "You have to change your password first.",
		codeUnauthenticated:        "You are not signed in.",
		codeCSRFFailed:             "The request did not come from this site.",
		codePolicyViolation:        "The password does not meet the requirements.",
		codeNotFound:               "Not found.",
		codeMethodNotAllowed:       "This method is not allowed here.",
		codeUnsupportedMediaType:   "Send the request as application/json.",
		codeInternal:               "Something went wrong. Try again later.",
		messageRequestTooLarge:     "The request is too large.",
	},
	"ru": { //nolint:gosec
		codeInvalidRequest:         "Некорректный запрос.",
		codeInvalidCredentials:     "Неверный логин или пароль.",
		codeUserBlocked:            "Учётная запись заблокирована.",
		codeRateLimited:            "Слишком много попыток. Повторите позже.",
		codePasswordChangeRequired: "Сначала нужно сменить пароль.",
		codeUnauthenticated:        "Вы не вошли в систему.",
		codeCSRFFailed:             "Запрос пришёл не с этого сайта.",
		codePolicyViolation:        "Пароль не соответствует требованиям.",
		codeNotFound:               "Не найдено.",
		codeMethodNotAllowed:       "Этот метод здесь не разрешён.",
		codeUnsupportedMediaType:   "Отправьте запрос как application/json.",
		codeInternal:               "Что-то пошло не так. Повторите позже.",
		messageRequestTooLarge:     "Запрос слишком большой.",
	},
}

type apiError struct {
	status  int
	code    string
	message string
	rules   []string
	header  http.Header
}

func newAPIError(code string) *apiError {
	return &apiError{status: statusOfCode[code], code: code, message: code}
}

func (e *apiError) with(name, value string) *apiError {
	if e.header == nil {
		e.header = http.Header{}
	}
	e.header.Set(name, value)
	return e
}

type errorBody struct {
	Error errorFields `json:"error"`
}

type errorFields struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Rules   []string `json:"rules,omitempty"`
}

func setCommonHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}

func writeError(w http.ResponseWriter, r *http.Request, e *apiError) {
	setCommonHeaders(w.Header())
	for name, values := range e.header {
		w.Header()[name] = values
	}
	language := negotiateLanguage(r.Header.Get("Accept-Language"))
	text, ok := messages[language][e.message]
	if !ok {
		text = messages[defaultLanguage][e.message]
	}
	writeJSON(w, e.status, errorBody{Error: errorFields{Code: e.code, Message: text, Rules: e.rules}})
}

func negotiateLanguage(header string) string {
	if len(header) > maxLanguageText {
		header = header[:maxLanguageText]
	}
	best, bestQuality := defaultLanguage, 0.0
	for i, part := range strings.Split(header, ",") {
		if i >= maxLanguages {
			break
		}
		tag, quality := parseLanguageRange(part)
		if quality <= bestQuality {
			continue
		}
		if _, supported := messages[tag]; supported {
			best, bestQuality = tag, quality
		}
	}
	return best
}

func parseLanguageRange(part string) (string, float64) {
	tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
	primary, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(tag)), "-")
	quality := 1.0
	for param := range strings.SplitSeq(params, ";") {
		name, value, found := strings.Cut(strings.TrimSpace(param), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil || parsed < 0 || parsed > 1 {
			return "", 0
		}
		quality = parsed
	}
	return primary, quality
}

func readJSON(w http.ResponseWriter, r *http.Request, into any, required bool) *apiError {
	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			e := newAPIError(codeInvalidRequest)
			e.status, e.message = http.StatusRequestEntityTooLarge, messageRequestTooLarge
			return e
		case err != nil:
			return newAPIError(codeInvalidRequest)
		}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if required {
			return newAPIError(codeInvalidRequest)
		}
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return newAPIError(codeUnsupportedMediaType)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(into); err != nil {
		return newAPIError(codeInvalidRequest)
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return newAPIError(codeInvalidRequest)
	}
	return nil
}

func retryAfterSeconds(d time.Duration) string {
	return strconv.FormatInt(int64(wholeSeconds(d)/time.Second), 10)
}
