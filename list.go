// SPDX-FileCopyrightText: 2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"strings"
)

// ListItem encapsulates the result of the "LIST" instruction.
type ListItem struct {
	ID         string
	Kind       Kind
	Algorithm  Algorithm
	Properties Properties
}

// String returns a string representation of the algorithm.
func (n *ListItem) String() string {
	details := []string{
		n.Algorithm.String(),
		n.Kind.String(),
	}

	if n.Properties > 0 {
		details = append(details, n.Properties.String())
	}

	return fmt.Sprintf("%s (%s)", n.ID, strings.Join(details, ", "))
}

// List sends a "LIST" instruction, return a list of credentials.
func (c *Card) List() ([]*ListItem, error) {
	var items []*ListItem
	var version byte = 1

	tvs, err := c.sendRaw(insList, 0x00, 0x00, []byte{version})
	if err != nil {
		return nil, err
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagNameList:
			item := &ListItem{}

			item.Algorithm = Algorithm(tv.Value[0] & 0x0f)
			item.Kind = Kind(tv.Value[0] & 0xf0)

			if c.info.SupportsExtendedList() {
				l := len(tv.Value)

				item.Properties = Properties(tv.Value[l-1])
				item.ID = string(tv.Value[1 : l-1])
			} else {
				item.Properties = 0
				item.ID = string(tv.Value[1:])
			}

			items = append(items, item)

		default:
			return nil, fmt.Errorf("%w (%#x)", errUnknownTag, tv.Tag)
		}
	}

	return items, nil
}
