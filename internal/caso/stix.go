package caso

import (
	"regexp"
	"strconv"
	"strings"
)

const MaxSTIXObjects = 5000

type STIXObject struct {
	ID          string           `json:"id"`
	Refs        []STIXRef        `json:"refs,omitempty"`
	Observation *STIXObservation `json:"observation,omitempty"`
	Origins     []STIXOrigin     `json:"origins,omitempty"`
}

type STIXObservation struct {
	First string `json:"first"`
	Last  string `json:"last"`
	Count int    `json:"count"`
}

type STIXOrigin struct {
	SourceName  string `json:"source_name"`
	ExternalID  string `json:"external_id"`
	Description string `json:"description,omitempty"`
}

func (origin STIXOrigin) Valid() bool {
	id, revision, found := strings.Cut(origin.ExternalID, "@")
	_, _, valid := recordPosition(id)
	value, err := strconv.Atoi(revision)
	return origin.SourceName == "PAVAROTTI" && found && valid && err == nil && value > 0 && strconv.Itoa(value) == revision
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
		if values, refs, found := strings.Cut(details, "\nReferencias\n"); found {
			lines := strings.SplitN(values, "\n", 4)
			if len(lines) == 3 {
				first, firstOK := strings.CutPrefix(lines[0], "Primera observación · ")
				last, lastOK := strings.CutPrefix(lines[1], "Última observación · ")
				number, _ := strings.CutPrefix(lines[2], "Observaciones · ")
				if count, err := strconv.Atoi(number); firstOK && lastOK && err == nil && count > 0 {
					object.Observation = &STIXObservation{First: first, Last: last, Count: count}
				}
			}
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
