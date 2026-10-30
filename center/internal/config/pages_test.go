// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"testing"
)

// TestThePagesSurfaceNeedsTheIdentitySurface (PLT-12): FLAGSHIP_SURFACES-style lists name pages only with identity; a self-hosted
// default enables both, and loses both when identity cannot be a relying party.
func TestThePagesSurfaceNeedsTheIdentitySurface(t *testing.T) {
	if got := KnownSurfaces(); len(got) != 3 || got[0] != SurfaceIdentity || got[1] != SurfacePages || got[2] != SurfaceOperations {
		t.Fatalf("known surfaces %v", got)
	}
	if got := DefaultSelfHostedSurfaces(); len(got) != 2 || got[0] != SurfaceIdentity || got[1] != SurfacePages {
		t.Fatalf("the self-hosted default surfaces %v", got)
	}
	hosted := func(surfaces string) map[string]string {
		return withIdentity(OfficialHosted, map[string]string{EnvSurfaces: surfaces, EnvClientIPHeader: ClientIPHeader})
	}
	loaded, err := Load(environment(hosted("identity,pages")))
	if err != nil || !loaded.Identity.Enabled(SurfaceIdentity) || !loaded.Identity.Enabled(SurfacePages) {
		t.Fatalf("identity,pages: %v %v", loaded.Identity.Surfaces, err)
	}
	for _, list := range []string{"pages", "pages,identity,pages", "identity,Pages", "identity, pages"} {
		if _, err = Load(environment(hosted(list))); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", list, err)
		}
	}
	if loaded, err = Load(environment(hosted("identity"))); err != nil || loaded.Identity.Enabled(SurfacePages) {
		t.Fatalf("identity alone: %v %v", loaded.Identity.Surfaces, err)
	}
	if loaded, err = Load(environment(hosted("none"))); err != nil || loaded.Identity.Enabled(SurfacePages) || loaded.Identity.Enabled(SurfaceIdentity) {
		t.Fatalf("none: %v %v", loaded.Identity.Surfaces, err)
	}
	// Self-hosted defaults to every surface; an IP-literal public base URL cannot be a relying party, so it leaves identity and the
	// pages off and says why.
	self := withIdentity(SelfHosted, map[string]string{})
	if loaded, err = Load(environment(self)); err != nil || !loaded.Identity.Enabled(SurfaceIdentity) || !loaded.Identity.Enabled(SurfacePages) {
		t.Fatalf("self-hosted default: %v %v", loaded.Identity.Surfaces, err)
	}
	self[EnvPublicBaseURL] = "https://192.0.2.10:8443"
	if loaded, err = Load(environment(self)); err != nil || loaded.Identity.Enabled(SurfaceIdentity) || loaded.Identity.Enabled(SurfacePages) || loaded.Identity.Disabled == "" {
		t.Fatalf("self-hosted on an address: %v %q %v", loaded.Identity.Surfaces, loaded.Identity.Disabled, err)
	}
}

func TestTheBasePathIsThePublicBaseURLsPath(t *testing.T) {
	for url, want := range map[string]string{
		"https://arcforges.com/api": "/api", "https://arcforges.com/api/": "/api", "https://arcforges.com": "", "https://arcforges.com/": "",
		"http://localhost:8080/center/v1": "/center/v1", "": "", "no scheme": "",
	} {
		if got := BasePath(url); got != want {
			t.Errorf("%q: %q, want %q", url, got, want)
		}
	}
}
