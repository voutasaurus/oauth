package oauth

func (h *Handler) acl(up *Profile) error {
	if h.ACL == nil {
		return nil
	}
	return h.ACL(up)
}
