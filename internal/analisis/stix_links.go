package analisis

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"

	"pavarotti/internal/caso"
)

var ErrSTIXPage = errors.New("paginación de relaciones STIX inválida")

type STIXLink struct {
	caso.STIXRef
	Incoming    bool      `json:"incoming,omitempty"`
	SamePackage bool      `json:"same_package,omitempty"`
	Evidence    *Evidence `json:"evidence,omitempty"`
}

type STIXLinks struct {
	ID       string     `json:"id"`
	Rows     []STIXLink `json:"rows"`
	Next     int        `json:"next,omitempty"`
	Previous int        `json:"previous"`
}

func RelatedSTIX(ctx context.Context, store *caso.Store, id string, offset int) (STIXLinks, error) {
	if offset < 0 {
		return STIXLinks{}, ErrSTIXPage
	}
	selected, err := store.Record(ctx, id)
	if err != nil {
		return STIXLinks{}, err
	}
	object := selected.STIXObject()
	if object.ID == "" {
		return STIXLinks{}, caso.ErrNotFound
	}
	targets := make(map[string][]STIXLink)
	for _, ref := range object.Refs {
		targets[ref.ID] = nil
	}
	incoming := make([]STIXLink, 0)
	err = walkEvidence(ctx, store, func(record caso.Record) {
		candidate := record.STIXObject()
		if candidate.ID == "" {
			return
		}
		samePackage := record.SHA256 != "" && record.SHA256 == selected.SHA256
		if matches, wanted := targets[candidate.ID]; wanted {
			evidence := reference(record)
			targets[candidate.ID] = append(matches, STIXLink{SamePackage: samePackage, Evidence: &evidence})
		}
		if record.ID == selected.ID {
			return
		}
		roles := make(map[string]bool)
		for _, ref := range candidate.Refs {
			if ref.ID == object.ID && !roles[ref.Role] {
				evidence := reference(record)
				incoming = append(incoming, STIXLink{STIXRef: caso.STIXRef{Role: ref.Role, ID: candidate.ID},
					Incoming: true, SamePackage: samePackage, Evidence: &evidence})
				roles[ref.Role] = true
			}
		}
	})
	if err != nil {
		return STIXLinks{}, err
	}
	for _, links := range targets {
		slices.SortFunc(links, compareSTIXLinks)
	}
	slices.SortFunc(incoming, compareSTIXLinks)
	rows := make([]STIXLink, 0, len(object.Refs)+len(incoming))
	seen := make(map[caso.STIXRef]bool)
	for _, ref := range object.Refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		links := targets[ref.ID]
		if len(links) == 0 {
			rows = append(rows, STIXLink{STIXRef: ref})
		}
		for _, link := range links {
			link.STIXRef = ref
			rows = append(rows, link)
		}
	}
	rows = append(rows, incoming...)
	if offset > len(rows) {
		return STIXLinks{}, ErrSTIXPage
	}
	end := min(offset+caso.DefaultPageSize, len(rows))
	page := STIXLinks{ID: object.ID, Rows: rows[offset:end], Previous: max(0, offset-caso.DefaultPageSize)}
	if end < len(rows) {
		page.Next = end
	}
	return page, nil
}

func compareSTIXLinks(left, right STIXLink) int {
	if left.SamePackage != right.SamePackage {
		if left.SamePackage {
			return -1
		}
		return 1
	}
	return cmp.Or(strings.Compare(left.ID, right.ID), strings.Compare(left.Role, right.Role),
		strings.Compare(left.Evidence.ID, right.Evidence.ID))
}
