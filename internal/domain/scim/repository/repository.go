package scimrepository

import (
	"context"

	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
)

type Repository interface {
	ListUserLinks(context.Context, string) ([]scimmodel.UserLink, error)
	GetUserLink(context.Context, string, string) (scimmodel.UserLink, bool, error)
	GetDeletedUserLinkByUserName(context.Context, string, string) (scimmodel.UserLink, bool, error)
	CreateUserLink(context.Context, scimmodel.UserLink) error
	RestoreUserLink(context.Context, scimmodel.UserLink, int64) (bool, error)
	UpdateUserLink(context.Context, scimmodel.UserLink, int64) (bool, error)
	DeleteUserLink(context.Context, string, string, int64) (bool, error)

	ListGroups(context.Context, string) ([]scimmodel.DirectoryGroup, error)
	GetGroup(context.Context, string, string) (scimmodel.DirectoryGroup, bool, error)
	CreateGroup(context.Context, scimmodel.DirectoryGroup) error
	UpdateGroup(context.Context, scimmodel.DirectoryGroup, int64) (bool, error)
	DeleteGroup(context.Context, string, string, int64) (bool, error)
}
