package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

func (h *Handler) writeProfile(w http.ResponseWriter, p *Profile) error {
	if h.WriteProfile == nil {
		return nil
	}
	return h.WriteProfile(w, p)
}

type Profile struct {
	ID            string `json:"-"`
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
	Locale        string `json:"locale"`
}

func (h *Handler) GetUserInfo(tok *oauth2.Token) (*Profile, error) {
	// TODO: populate this URL from the Directory URL
	req, err := http.NewRequest("GET", h.UserInfo, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if code := res.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("userinfo lookup error: %s, status: %d", res.Status, res.StatusCode)
	}
	var v Profile
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
