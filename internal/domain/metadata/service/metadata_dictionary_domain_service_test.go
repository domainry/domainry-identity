// Dictionary domain service tests.
package service

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	"testing"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
)

type dictionaryRuntimeRepository struct {
	metadatarepository.MetadataRepository
	localized []metadatamodel.LocalizedText
}

func (r dictionaryRuntimeRepository) ListLocalizedTexts(context.Context, string, metadatamodel.LocalizedTextQuery) ([]metadatamodel.LocalizedText, error) {
	return append([]metadatamodel.LocalizedText(nil), r.localized...), nil
}

func TestDictionaryRuntimeOwnsStableVersionCacheAndLocalization(t *testing.T) {
	dictionaries := []metadatamodel.DictionarySchema{{Key: "status", Items: []metadatamodel.DictionaryItemSchema{{Key: "active", Value: "active", Label: "Active"}, {Key: "active", Value: "active", Label: "Aktiv", Locale: "de"}}}}
	firstVersion, secondVersion := DictionarySchemaVersion(dictionaries), DictionarySchemaVersion(dictionaries)
	if firstVersion == 0 || firstVersion != secondVersion {
		t.Fatalf("content version drifted: %d vs %d", firstVersion, secondVersion)
	}
	runtime := NewMetadataDictionaryDomainService(dictionaries)
	repository := dictionaryRuntimeRepository{localized: []metadatamodel.LocalizedText{{EntityKey: "status.active", Property: "description", Locale: "de", Text: "Kann verwendet werden"}}}
	principal := identitymodel.Principal{Known: true}
	first, cached, err := runtime.Items(t.Context(), repository, "status", "de", principal)
	if err != nil || cached || len(first.Items) != 1 || first.Items[0].Label != "Aktiv" || first.Items[0].Description != "Kann verwendet werden" {
		t.Fatalf("first=%#v cached=%v err=%v", first, cached, err)
	}
	second, cached, err := runtime.Items(t.Context(), repository, "status", "de", principal)
	if err != nil || !cached || !second.Cached || second.Version != first.Version {
		t.Fatalf("second=%#v cached=%v err=%v", second, cached, err)
	}
	runtime.Invalidate()
	third, cached, err := runtime.Items(t.Context(), repository, "status", "de", principal)
	if err != nil || cached || third.Version == first.Version {
		t.Fatalf("third=%#v cached=%v err=%v", third, cached, err)
	}
}
