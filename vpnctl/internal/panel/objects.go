package panel

import (
	"regexp"
	"strings"
)

var (
	profileNamePattern = regexp.MustCompile(`^[A-Za-z0-9_ -]{2,30}$`)
	snippetNamePattern = regexp.MustCompile(`^[A-Za-z0-9_ -]+(/[A-Za-z0-9_ -]+)*$`)
	hostNamePattern    = regexp.MustCompile(`^[A-Za-z0-9_ -]{1,100}$`)
	objectUUIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// LoadObjects reads a strict, bounded declaration file. It never reads credentials.
func LoadObjects(path string) (Objects, error) {
	data, err := readRegularJSON(path)
	if err != nil {
		return Objects{}, err
	}
	var objects Objects
	if err := decodeStrict(data, &objects); err != nil {
		return Objects{}, err
	}
	if err := objects.Validate(); err != nil {
		return Objects{}, err
	}
	return objects, nil
}

// Validate checks declaration identities and references before panel I/O.
func (o Objects) Validate() error {
	if o.Schema != 1 {
		return ErrInvalidInput
	}
	if len(o.Profiles)+len(o.Snippets)+len(o.Hosts) == 0 {
		return ErrInvalidInput
	}
	profiles := make(map[string]ProfileSpec, len(o.Profiles))
	profileIDs := make(map[string]bool, len(o.Profiles))
	for _, spec := range o.Profiles {
		if !profileNamePattern.MatchString(spec.Name) || strings.TrimSpace(spec.Name) != spec.Name {
			return ErrInvalidInput
		}
		if spec.Name == "Default-Profile" || !bundleRole(spec.Role) {
			return ErrInvalidInput
		}
		if _, exists := profiles[spec.Name]; exists {
			return ErrInvalidInput
		}
		if spec.UUID != "" {
			if !objectUUID(spec.UUID) || profileIDs[spec.UUID] {
				return ErrInvalidInput
			}
			profileIDs[spec.UUID] = true
		}
		profiles[spec.Name] = spec
	}
	snippets := make(map[string]SnippetSpec, len(o.Snippets))
	for _, spec := range o.Snippets {
		validName := len(spec.Name) >= 2 && len(spec.Name) <= 255 && snippetNamePattern.MatchString(spec.Name)
		if !validName || strings.TrimSpace(spec.Name) != spec.Name {
			return ErrInvalidInput
		}
		if !bundleRole(spec.Role) || !snippetField(spec.Field) {
			return ErrInvalidInput
		}
		if _, exists := snippets[spec.Name]; exists {
			return ErrInvalidInput
		}
		snippets[spec.Name] = spec
	}
	for _, profile := range o.Profiles {
		fields := make(map[string]bool, len(profile.Snippets))
		for _, name := range profile.Snippets {
			snippet, exists := snippets[name]
			if !exists || snippet.Role != profile.Role || fields[snippet.Field] {
				return ErrInvalidInput
			}
			fields[snippet.Field] = true
		}
	}
	hosts := make(map[string]bool, len(o.Hosts))
	hostIDs := make(map[string]bool, len(o.Hosts))
	bindings := make(map[string]bool, len(o.Hosts))
	for _, spec := range o.Hosts {
		if !hostNamePattern.MatchString(spec.Name) || strings.TrimSpace(spec.Name) != spec.Name || hosts[spec.Name] {
			return ErrInvalidInput
		}
		profile, exists := profiles[spec.Profile]
		if !exists || !publicInbound(profile.Role, spec.Inbound, spec.Family) {
			return ErrInvalidInput
		}
		if spec.Family != "ipv4" && spec.Family != "ipv6" {
			return ErrInvalidInput
		}
		if spec.UUID != "" {
			if !objectUUID(spec.UUID) || hostIDs[spec.UUID] {
				return ErrInvalidInput
			}
			hostIDs[spec.UUID] = true
		}
		binding := spec.Profile + "/" + spec.Inbound + "/" + spec.Family
		if bindings[binding] {
			return ErrInvalidInput
		}
		bindings[binding] = true
		hosts[spec.Name] = true
	}
	return nil
}

func bundleRole(role string) bool { return role == "exit" || role == "relay" }

func objectUUID(value string) bool {
	return objectUUIDPattern.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}

func snippetField(field string) bool {
	switch field {
	case "outbounds", "routing.rules", "routing.balancers":
		return true
	default:
		return false
	}
}
