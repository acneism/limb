// Package limb is an embeddable authentication library for Go.
// It provides password authentication with developer-defined login identifiers,
// cookie sessions and JWT, an embedded web admin panel, and database-agnostic
// storage built on database/sql.
//
// # Sessions
//
// Login checks a login and a password and opens a session of one of two kinds. A
// cookie session is carried by the browser in a cookie: limb returns its secret,
// which it keeps only as a hash, and a CSRF token that the page sends back in the
// X-CSRF-Token header of requests that change data. A token session is carried by
// an access token and a refresh token. Every sign-in has a session of its own, and
// the session ends when the user signs out, when it has lived for its absolute
// lifetime, when it has not been used for its idle lifetime, or when the user
// is blocked or deleted. Authenticate finds who makes a request, from a
// Bearer token if there is one and from the cookie otherwise.
//
// # Access tokens
//
// An access token is a JWT that names a user and one of their sessions and
// carries nothing else about them. Services that verify the tokens themselves
// read the keys from the JWKS that the HTTP handler publishes and must check the
// header and the claims as follows.
//
// The header has three fields: alg, the algorithm of WithSigningAlgorithm, which
// is EdDSA unless set otherwise; kid, the identifier of the key in the JWKS; and
// typ, which is always "at+jwt".
//
// The claims are:
//
//	iss  the issuer, "limb" unless set with WithTokenIssuer
//	sub  the ID of the user
//	aud  the audience, the issuer unless set with WithTokenAudience; a token is
//	     accepted only if the audience it names is the one that is configured
//	sid  the ID of the session the token belongs to
//	iat  when the token was issued, in seconds
//	exp  when the token expires, in seconds; 10 minutes after iat unless set
//	     with WithAccessTokenTTL
//	cpw  true, and present only then, while the user must change the password
//	     before doing anything else; a service must not give such a token access
//
// The signing keys are made by limb, replaced every 30 days and published ahead
// of time: a new key is in the JWKS for at least as long as a client may cache
// the list before it signs its first token. A token must be refused when it is
// longer than 8 KiB, when its algorithm is not the expected one, when its key is
// not in the JWKS, when the signature is wrong, when the issuer, the audience or
// the type are wrong, and when it has expired; a time tolerance of a few seconds
// is enough for clocks that differ a little.
//
// With the default revocation mode every token is also checked against the
// database, so ending a session or blocking a user takes effect at once. A
// service that cannot reach the application has to live with the lifetime of the
// token, or ask limb: see WithServiceKey.
//
// # Registration
//
// Register makes a user for the code of the application. Signup is for visitors,
// stands behind POST /register and works only with WithSignup: it checks the
// values and the password, counts the request in the limits of recovery, asks the
// hook BeforeRegister, which may refuse it, for example for a wrong invitation
// code in Registration.Extra, and stores the user. Its answer does not tell
// whether an e-mail address or a phone number is taken: the registration that
// uses one returns as if it had succeeded, creates nothing and sends the owner a
// notice, while a nickname that is taken is reported, since it has to be chosen.
// When WithSignup is given and the service has an identifier type that is a
// delivery channel, a user signs in only after confirming one address or phone
// number, and Login returns ErrVerificationRequired until then;
// Registration.Verified lets the code of the application confirm values when it
// makes a user, and WithoutVerificationRequired turns the requirement off.
//
// # Confirmation and recovery
//
// A message that confirms an address or a phone number, and one that lets the
// user choose a new password, carries a link and a code. The link is the address
// given with WithVerifyURL or WithResetURL with the secret in its fragment, which
// a browser does not send to a server, and the page of the application reads it
// and sends it in the body of a request; the code has six digits. A link works
// for 24 hours when it confirms an address and for 30 minutes when it resets a
// password, a code for ten minutes and five guesses, wrong or right, and each
// works once and ends the other. The database holds only hashes: the SHA-256 of
// the token of a link, and a keyed hash of a code that is bound to the user, to the
// purpose and to the channel it was sent to. RequestVerification, Verify,
// RequestPasswordReset and ResetPassword do it in code. A reset goes only to a
// channel that is confirmed, ends every session of the user unless
// WithKeepSessionsAfterReset is given and checks the new password against the
// password policy. The answer to a request for a message is the same for a login
// that has an account and one that has not, and ChangePassword and ResetPassword
// tell the user, by a message on every confirmed channel, that the password was
// changed.
//
// # Messages
//
// limb does not send messages itself. The application gives WithSender an
// implementation of Sender, which gets a Message with its kind, the recipient, the
// language, the link and the code, and a text made from the templates for Russian
// and English that limb has built in. WithMessageTemplate replaces a template of a
// kind and a language and WithServiceName names the service in the texts. A
// request only counts its limits and puts a task in a queue, and workers send in
// the background, once and with a timeout, see WithSending, so the answer does not
// depend on the account or on the Sender; a full queue returns ErrBusy. Call
// Shutdown when the application stops.
//
// # Hooks and events
//
// WithHooks gives limb functions to call. BeforeRegister can refuse a
// registration. OnEvent is called after an operation has been committed, with an
// Event that holds no password, link, token or code, when a user is created, signs
// in or fails to, signs out, changes or resets the password, confirms a channel or
// loses a session, when a refresh token is used again and when a message cannot be
// sent. A panic in a hook is contained and logged. The one event that a worker
// delivers after the answer is the user that Signup created, so that a slow hook
// cannot show whether an address was taken, and Shutdown waits for it.
//
// # Limits
//
// Failed sign-ins are counted in the database, for an account from one address,
// for an address and for an account, and the next attempts are turned down with a
// *RateLimitError before the password is looked at, see WithLoginLimits. The
// account is never locked: its attempts are only slowed down. Registrations and
// requests for messages are counted for the address of the client and for the
// address, the phone number or the login that they name, whether or not an account
// has it, and wrong links and codes for the address of the client, see
// WithRecoveryLimits. Each user gets five messages of a kind in an hour, and the
// others are not sent.
//
// # HTTP
//
// Handler serves the routes for signing in and out, for the sessions of the user
// and for tokens as a JSON API, and, where the service allows it, those for
// registration, confirmation and recovery. It publishes the keys that verify
// access tokens. The application mounts it under a path of its choice. RequireAuth and
// OptionalAuth wrap the handlers of the application: they find who made the
// request by the rules of Authenticate and keep the answer in the context, where
// CurrentUser finds it. An application that needs other routes or other answers
// calls Login, Authenticate, Refresh and the rest directly. limb never sets CORS
// headers: an application whose single-page client lives on another origin adds
// them itself, in front of the handler.
package limb
