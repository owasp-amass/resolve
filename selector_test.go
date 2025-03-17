// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

/*
func TestAuthGetResolver(t *testing.T) {
	r := NewResolvers()
	defer r.Stop()

	auth := r.pool.(*authNSSelector)
	r.SetTimeout(500 * time.Millisecond)
	res := auth.GetResolver("www.utica.edu")
	if res == nil {
		t.Errorf("Failed to obtain the resolver for www.utica.edu")
	}
}

func TestPopulateAuthServers(t *testing.T) {
	r := NewResolvers()
	defer r.Stop()

	auth := r.pool.(*authNSSelector)
	r.SetTimeout(500 * time.Millisecond)
	auth.populateAuthServers("utica.edu")
	if res, found := auth.fqdnToResolvers["utica.edu"]; !found || len(res) != 2 {
		t.Errorf("Failed to obtain the name servers")
	}
}

func TestServerNameToResolverObj(t *testing.T) {
	r := NewResolvers()
	defer r.Stop()

	auth := r.pool.(*authNSSelector)
	r.SetTimeout(500 * time.Millisecond)
	res := auth.serverNameToResolverObj("a.edu-servers.net", pickOneResolver(auth.rootResolvers))
	if res == nil {
		t.Errorf("Failed to obtain the resolver object for a.edu-servers.net")
	}
}

func TestGetNameServers(t *testing.T) {
	r := NewResolvers()
	defer r.Stop()

	wanted := stringset.New(
		"a.edu-servers.net",
		"b.edu-servers.net",
		"c.edu-servers.net",
		"d.edu-servers.net",
		"e.edu-servers.net",
		"f.edu-servers.net",
		"g.edu-servers.net",
		"h.edu-servers.net",
		"i.edu-servers.net",
		"j.edu-servers.net",
		"k.edu-servers.net",
		"l.edu-servers.net",
		"m.edu-servers.net",
	)

	auth := r.pool.(*authNSSelector)
	r.SetTimeout(500 * time.Millisecond)
	servers := auth.getNameServers("edu", pickOneResolver(auth.rootResolvers))
	if len(servers) == 0 {
		t.Errorf("Failed to obtain the .edu servers")
		return
	}
	got := stringset.New(servers...)

	wanted.Subtract(got)
	if wanted.Len() > 0 {
		t.Errorf("Failed to obtain the correct .edu servers")
	}
}
*/
