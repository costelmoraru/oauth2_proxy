package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	oauth2 "golang.org/x/oauth2"

	oidc "github.com/coreos/go-oidc"
)

// OIDCProvider represents an OIDC based Identity Provider
type OIDCIBMProvider struct {
	*ProviderData

	Verifier *oidc.IDTokenVerifier
}

// NewOIDCProvider initiates a new OIDCProvider
func NewOIDCIBMProvider(p *ProviderData) *OIDCIBMProvider {
	p.ProviderName = "IBM's OpenID Connect"
	return &OIDCIBMProvider{ProviderData: p}
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCIBMProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}

	// 20180629 - TL: Added logging
	fmt.Printf("Client ID: %s\n", p.ClientID)
	fmt.Printf("Client Secret: %s\n", p.ClientSecret)
	fmt.Printf("Token URL: %s\n", p.RedeemURL.String())
	fmt.Printf("Redirect URL: %s\n", redirectURL)
	fmt.Printf("Code: %s\n", code)

	// 20180629 - TL: Add in a parameter to handle registering broken oauth2's
	oauth2.RegisterBrokenAuthHeaderProvider(p.RedeemURL.String())

	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}
	fmt.Printf("Token: %v\n", token)
	s, err = p.createSessionState(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}
	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *OIDCIBMProvider) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	fmt.Printf("RefreshSessionIfNeeded() - %v\n", s)
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		// the two commented lines below are hard coding the session timeout to two minutes
		//if s == nil || s.ExpiresOn.After(time.Now().Add(time.Hour*time.Duration(1)+
		//	time.Minute*time.Duration(58))) || s.RefreshToken == "" {
		fmt.Printf("RefreshSessionIfNeeded() - Expiry not yet reached, no session, or refresh token.\n")
		return false, nil
	}
	//return false, fmt.Errorf("Clear Session and start again")

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(s)
	if err != nil {
		fmt.Printf("RefreshSessionIfNeeded() - Error: %v\n", err)
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *OIDCIBMProvider) redeemRefreshToken(s *SessionState) (err error) {
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	ctx := context.Background()
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	fmt.Printf("redeemRefreshToken() - token: %v\n", token)
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	newSession, err := p.createSessionState(ctx, token)
	if err != nil {
		return fmt.Errorf("unable to update session: %v", err)
	}

	s.AccessToken = newSession.AccessToken
	s.IDToken = newSession.IDToken
	s.RefreshToken = newSession.RefreshToken
	s.ExpiresOn = newSession.ExpiresOn
	s.Email = newSession.Email

	//s.AccessToken = token.Extra("access_token").(string)
	//s.RefreshToken = token.Extra("refresh_token").(string)
	//s.ExpiresOn = s.ExpiresOn.Add(time.Second * time.Duration(token.Extra("expires_in")))
	//s.ExpiresOn = s.ExpiresOn.Add(time.Second * time.Duration(7100))
	return
}

func (p *OIDCIBMProvider) createSessionState(ctx context.Context, token *oauth2.Token) (*SessionState, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	fmt.Printf("createSessionState() - rawIDToken: %v\n", rawIDToken)
	//fmt.Printf("createSessionState() - rawAccessToken: %v\n", rawAccessToken)
	if !ok {
		fmt.Printf("createSessionState() - ok: %v\n", ok)
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// 20180629 - TL: Added logging
	fmt.Printf("Raw IDToken: %s\n", rawIDToken)

	// Parse and verify ID Token payload.
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	// 20180629 - TL: adjusted email string to match IBM
	var claims struct {
		Email    string `json:"emailAddress"`
		Verified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("id_token did not contain an email")
	}
	if claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	// // 20180629 - TL: Remove unnecessary bloat due to BlueGroups
	bmrgIDToken, err := removeBlueGroupsInIDToken(rawIDToken)
	if err != nil {
		fmt.Errorf("Unable to Remove Blue Groups in ID Token: %v", err)
		bmrgIDToken = rawIDToken
	}
	fmt.Printf("Boomerang IDToken: %s\n", bmrgIDToken)

	fmt.Printf("Boomerang Refresh Token: %s\n", token.RefreshToken)

	return &SessionState{
		AccessToken: token.AccessToken,
		// IDToken:     rawIDToken,
		IDToken:      bmrgIDToken,
		RefreshToken: token.RefreshToken,
		ExpiresOn:    token.Expiry,
		Email:        claims.Email,
	}, nil
}

// ValidateSessionState checks that the session's IDToken is still valid
func (p *OIDCIBMProvider) ValidateSessionState(s *SessionState) bool {
	//ctx := context.Background()
	//_, err := p.Verifier.Verify(ctx, s.IdToken)
	//if err != nil {
	// 20180629 - TL: Testing. This should be set back to return false and log removed.
	//fmt.Printf("oidcibm ValidateSessionState() Error: %s\n...Returning VALID for IBM.", err)
	//return false
	//}

	// 20180703 - TL: Logging and testing.
	//fmt.Printf("oidcibm ValidateSessionState() - Returning VALID for IBM.", err)
	// return true
	ctx := context.Background()
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		return false
	}

	return true
}

func removeBlueGroupsInIDToken(p string) (string, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("oidcibm removeBlueGroupsInIDToken() - malformed jwt, expected 3 parts got %d", len(parts))
	}
	bytePayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidcibm removeBlueGroupsInIDToken() - malformed jwt payload: %v", err)
	}
	//fmt.Printf("Original Payload: %q\n", bytePayload)
	var jsonPayload map[string]interface{}
	json.Unmarshal(bytePayload, &jsonPayload)
	for k := range jsonPayload {
		if k == "blueGroups" {
			delete(jsonPayload, k)
		}
	}
	bytePayload2, err := json.Marshal(jsonPayload)
	//fmt.Printf("Payload no BlueGroups: %q\n", bytePayload2)
	parts[1] = base64.RawURLEncoding.EncodeToString(bytePayload2)

	return strings.Join(parts, "."), nil
}
