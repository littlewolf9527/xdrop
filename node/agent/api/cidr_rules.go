package api

func prefixReferences(rules map[string]StoredCIDRRule) [2][]string {
	var refs [2][]string
	for _, r := range rules {
		for d, prefix := range []string{r.SrcCIDR, r.DstCIDR} {
			if prefix != "" {
				refs[d] = append(refs[d], prefix)
			}
		}
	}
	return refs
}

func (p *commitPlan) retiredPrefixes() [2][]string {
	var refs [2][]string
	for _, g := range p.Groups {
		if g.Changed {
			for _, r := range g.Old {
				for d, prefix := range []string{r.SrcCIDR, r.DstCIDR} {
					if prefix != "" {
						refs[d] = append(refs[d], prefix)
					}
				}
			}
		}
	}
	return refs
}
