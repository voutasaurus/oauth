package oauth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"time"
)

var (
	ErrCookieExpired = errors.New("cookie expired")
	ErrCookieDomain  = errors.New("cookie used for wrong domain")
	ErrInvalidCipher = errors.New("Invalid Cipher: could not decrypt bytes provided")
)

func (h *Handler) cookieName() string {
	if h.CookieName == "" {
		return "session"
	}
	return h.CookieName
}

func (h *Handler) setCookie(w http.ResponseWriter, in []byte) {
	dcheck := append([]byte(h.Domain), byte(' ')) // delimiter
	tb := make([]byte, len(in)+8+len(dcheck))

	// Ensure user doesn't mess with the time
	now := time.Now()
	binary.BigEndian.PutUint64(tb, uint64(now.Unix()))

	// Ensure user doesn't mess with the domain
	copy(tb[8:], dcheck)

	// Ensure user doesn't mess with the payload
	copy(tb[8+len(dcheck):], in)

	out, err := encryptBytes(h.CookieKey, tb)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.cookieName(),
		Value:    base64.URLEncoding.EncodeToString(out),
		Expires:  now.Add(24 * time.Hour),
		Path:     "/", // ALL PATHS
		Domain:   h.Domain,
		Secure:   true, // DON'T SEND UNENCRYPTED
		HttpOnly: true, // NO CLIENT SIDE SHENANIGANS
	})
}

func (h *Handler) Cookie(r *http.Request) ([]byte, error) {
	c, err := r.Cookie(h.cookieName())
	if err != nil {
		return nil, err
	}
	in, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, err
	}
	b, err := decryptBytes(h.CookieKey, in)
	if err != nil {
		return nil, err
	}

	ts := binary.BigEndian.Uint64(b)
	if time.Since(time.Unix(int64(ts), 0)) > 24*time.Hour {
		return nil, ErrCookieExpired
	}
	b = b[8:]

	dcheck := []byte(h.Domain)
	bb := bytes.Split(b, []byte(" "))
	if !bytes.Equal(bb[0], dcheck) {
		return nil, ErrCookieDomain
	}
	b = bytes.Join(bb[1:], []byte(" "))

	return b, nil
}
