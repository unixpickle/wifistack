package wifistack

import (
	"bytes"

	"github.com/unixpickle/wifistack/frames"
)

// partialMSDU represents an MSDU which has arrived in pieces.
type partialMSDU struct {
	hasLastFragment bool
	fragments       [][]byte
}

// handleFrame takes the data from a data frame and adds it to this MSDU.
func (p *partialMSDU) handleFrame(f *frames.Frame) {
	idx := int((*f.SequenceControl) & 0xf)
	if !f.MoreFrag {
		p.hasLastFragment = true
	}
	for idx >= len(p.fragments) {
		p.fragments = append(p.fragments, nil)
	}
	p.fragments[idx] = f.Payload
}

// complete returns whether or not every piece of the underlying MSDU has been received.
func (p *partialMSDU) complete() bool {
	if !p.hasLastFragment {
		return false
	}
	for _, x := range p.fragments {
		if x == nil {
			return false
		}
	}
	return true
}

// msdu reconstructs the original MSDU and returns it.
// You should only use this if complete() returns true.
func (p *partialMSDU) msdu() []byte {
	var buf bytes.Buffer
	for _, x := range p.fragments {
		buf.Write(x)
	}
	return buf.Bytes()
}
