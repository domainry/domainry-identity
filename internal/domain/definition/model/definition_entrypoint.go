package definitionmodel

import localizationmodel "github.com/domainry/domainry-identity/internal/domain/localization/model"

type EntryPointSchema struct {
	Key         string                             `json:"key"`
	Name        string                             `json:"name,omitempty"`
	Description string                             `json:"description,omitempty"`
	I18n        localizationmodel.LocalizedTextMap `json:"i18n,omitempty"`
	Audience    string                             `json:"audience,omitempty"`
	Roles       []string                           `json:"roles,omitempty"`
	Default     bool                               `json:"default,omitempty"`
	Config      map[string]any                     `json:"config,omitempty"`
}
