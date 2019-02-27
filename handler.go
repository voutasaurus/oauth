package oauth

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

type Handler struct {
	// Config is the oauth2 config including client ID and client secret.
	// Config must be set.
	oauth2.Config

	// StateKey is the key used in the OAuth2 flow to encrypt the state
	// across the redirect. A consistent State key is required across the
	// services executing HandleLogin and the HandleRedirect. This key can
	// be rotated freely as it is only necessary to be consistent accross a
	// single OAuth flow. StateKey must be set.
	//
	// See NewKey to generate new keys of this type and for further
	// documentation.
	StateKey *[32]byte

	// CookieKey is the key used to encrypt and decrypt cookies. A
	// consistent Cookie key is required across the services running
	// HandleRedirect and GetCookie. Rotating this key will log all users
	// out (their cookies will be invalid). CookieKey must be set.
	//
	// See NewKey to generate new keys of this type and for further
	// documentation.
	//
	// TODO: providing an option of a slice of keys here for decryption
	// will allow for a seamless rotation to occur across MaxAge.
	CookieKey *[32]byte

	// Domain is the fully qualified domain name that the cookies will be
	// restricted to. Cookies from other domains will not normally be sent
	// by browsers. This field is used to make sure on the server side that
	// cookies are not reused across domains. This is important if you are
	// using this package for a service for multiple domains. Domain must
	// be set.
	Domain string

	// CookieName is the name to be given to the session cookie when it is
	// set in the user's browser. Defaults to "session".
	CookieName string

	// Service (e.g. microsoft, google, etc) is prepended to the subject ID
	// of the oauth user and the result is used as the preencrypted cookie
	// payload. This allows for a more straightforward migration from a
	// single OAuth provider to multiple OAuth providers by keeping the ID
	// spaces clearly dilineated and ensuring uniqueness. The composite ID
	// is also given in the Profile info to WriteProfile. Service must be
	// set.
	Service string

	// UserInfo is the URL with which to look up user profile information.
	//
	// e.g. "https://openidconnect.googleapis.com/v1/userinfo"
	//
	// UserInfo must be set
	UserInfo string

	// WriteProfile is an optional callback function to upload profile
	// information from authenticated users to a database for use in
	// authorization. See the Profile type for more information. Defaults
	// to a no-op.
	WriteProfile func(http.ResponseWriter, *Profile) error

	// FinalizeLogin defaults to http.Redirect(w, r, "/", 307) and is
	// called after the redirect is complete and cookie is issued.
	FinalizeLogin http.HandlerFunc

	// ACL is an optional access control list function. Return an error if
	// the user is not allowed. By default all users are allowed.
	ACL func(*Profile) error

	// Log is an optional logger for debugging. Defaults to a no-op logger.
	Log *log.Logger
}

func (h *Handler) log() *log.Logger {
	if h.Log != nil {
		return h.Log
	}
	return log.New(ioutil.Discard, "", 0)
}

func (h *Handler) finalizeLogin(w http.ResponseWriter, r *http.Request) {
	if h.FinalizeLogin != nil {
		h.FinalizeLogin(w, r)
		return
	}
	http.Redirect(w, r, "/", 307)
}

// HandleLogin will redirect the user to Google's consent page to ask for
// permission for the scopes specified in the Handler Config.
//
// Use this when the user is not authenticated and the current GET request
// requires authorization. For POSTS you should just fail and expect the user
// to log on before posting.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	_, err := h.Cookie(r)
	if err == nil {
		// If cookie is present and good, redirect to home as
		// authentication is complete.
		h.finalizeLogin(w, r)
		return
	}

	if err != http.ErrNoCookie {
		// If cookie is present but bad, delete it now.
		h.HandleLogoff(w, r)
	}

	// Now cookie is not present, procede with OAuth

	origin := r.URL.String()
	b, err := EncryptBytes(h.StateKey, []byte(origin))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	url := h.AuthCodeURL(base64.URLEncoding.EncodeToString(b))
	http.Redirect(w, r, url, 307)
}

// HandleLogoff will invalidate the cookie in the user's browser.
func (h *Handler) HandleLogoff(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.CookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		Domain:   h.Domain,
		Secure:   true,
		HttpOnly: true,
	})
}

// HandleRedirect gets the redirect from Google OAuth with the authorization
// codes, retrieves the scopes from the identity provider, issues a cookie, and
// redirects to the original URL.
func (h *Handler) HandleRedirect(w http.ResponseWriter, r *http.Request) {
	// TODO: differentiate user facing errors from debug errors
	rawState, err := base64.URLEncoding.DecodeString(r.FormValue("state"))
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	b, err := DecryptBytes(h.StateKey, rawState)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	home := string(b)

	tok, err := h.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}

	up, err := h.GetUserInfo(tok)
	if err != nil {
		http.Error(w, "userinfo request error: "+err.Error(), 500)
		return
	}

	if err != h.acl(up) {
		http.Error(w, "ACL error: "+err.Error(), 500)
		return
	}

	up.ID = h.Service + "_" + up.Sub
	h.writeProfile(w, up)

	h.SetCookie(w, []byte(up.ID))
	http.Redirect(w, r, home, 307)
	// the user will be taken back to the page they originally tried to
	// access. In the basic case this is whatever endpoint HandleLogin is
	// serving for.
}
