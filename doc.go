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
// # Limits
//
// Failed sign-ins are counted in the database, for an account from one address,
// for an address and for an account, and the next attempts are turned down with a
// *RateLimitError before the password is looked at, see WithLoginLimits. The
// account is never locked: its attempts are only slowed down.
package limb
