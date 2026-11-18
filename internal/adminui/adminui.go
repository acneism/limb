// Package adminui holds what the web administration shows: the templates of its
// pages, the texts in the languages that it speaks, the stylesheet and the QR
// code that binds an authenticator. They are embedded in the library, and the
// pages need nothing from any other site and run no script. The package knows
// nothing of sessions and stores: the handler of the administration gives it data
// and it makes HTML.
package adminui
