package caso

import (
	"regexp"
	"strings"
)

type STIXObject struct {
	ID   string    `json:"id"`
	Refs []STIXRef `json:"refs,omitempty"`
}

type STIXRef struct {
	Role string `json:"role"`
	ID   string `json:"id"`
}

var stixID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,249}--[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func ValidSTIXID(value string) bool { return len(value) <= 288 && stixID.MatchString(value) }

func (record Record) STIXObject() STIXObject {
	if record.Kind != "stix" {
		return STIXObject{}
	}
	if record.STIX != nil && ValidSTIXID(record.STIX.ID) {
		return *record.STIX
	}
	line, details, _ := strings.Cut(record.Details, "\n")
	id, found := strings.CutPrefix(line, "Objeto STIX · ")
	if !found || !ValidSTIXID(id) {
		return STIXObject{}
	}
	object := STIXObject{ID: id}
	if strings.HasPrefix(id, "observed-data--") {
		if _, refs, found := strings.Cut(details, "\nReferencias\n"); found {
			for ref := range strings.SplitSeq(refs, "\n") {
				if ValidSTIXID(ref) && len(object.Refs) < 256 {
					object.Refs = append(object.Refs, STIXRef{Role: "observado", ID: ref})
				}
			}
		}
	} else if strings.HasPrefix(id, "relationship--") {
		first, last, _ := strings.Cut(details, "\n")
		source, _ := strings.CutPrefix(first, "Origen · ")
		target, _ := strings.CutPrefix(last, "Destino · ")
		if ValidSTIXID(source) && ValidSTIXID(target) {
			object.Refs = []STIXRef{{Role: "origen", ID: source}, {Role: "destino", ID: target}}
		}
	}
	return object
}
