// Package protocol provides the registry that maps ports and payload signatures
// to the correct protocol parser.
package protocol

// Registry maintains a set of parsers indexed by well-known port numbers.
type Registry struct {
	byPort map[uint16][]Parser
	all    []Parser
}

// NewRegistry returns an empty, ready-to-use Registry.
func NewRegistry() *Registry {
	return &Registry{
		byPort: make(map[uint16][]Parser),
	}
}

// Register adds a parser to the registry, indexing it under every port the
// parser declares via Ports().
func (r *Registry) Register(p Parser) {
	r.all = append(r.all, p)
	for _, port := range p.Ports() {
		r.byPort[port] = append(r.byPort[port], p)
	}
}

// Resolve picks the best parser for the given connection.
//
// Strategy:
//  1. Look up parsers registered for dstPort. If exactly one matches, return
//     it immediately.
//  2. If multiple parsers share the same port, run Probe on each and return
//     the one with the highest confidence score.
//  3. If no parser is registered for dstPort, fall back to a full Probe scan
//     over every registered parser.
//
// Returns nil when no parser claims the data.
func (r *Registry) Resolve(srcPort, dstPort uint16, sample []byte, isFromClient bool) Parser {
	// Step 1 & 2: port-based lookup.
	if candidates := r.byPort[dstPort]; len(candidates) == 1 {
		return candidates[0]
	} else if len(candidates) > 1 {
		return r.bestProbe(candidates, sample, isFromClient)
	}

	// Also check srcPort (for responses flowing back from a known server port).
	if candidates := r.byPort[srcPort]; len(candidates) == 1 {
		return candidates[0]
	} else if len(candidates) > 1 {
		return r.bestProbe(candidates, sample, isFromClient)
	}

	// Step 3: brute-force probe.
	return r.bestProbe(r.all, sample, isFromClient)
}

// bestProbe returns the parser with the highest Probe score, or nil if every
// parser returned 0.
func (r *Registry) bestProbe(parsers []Parser, sample []byte, isFromClient bool) Parser {
	var best Parser
	bestScore := 0
	for _, p := range parsers {
		if s := p.Probe(sample, isFromClient); s > bestScore {
			bestScore = s
			best = p
		}
	}
	return best
}
