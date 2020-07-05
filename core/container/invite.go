package container

import (
	"github.com/bitmaelum/bitmaelum-server/core/invite"
	"github.com/bitmaelum/bitmaelum-server/internal/config"
	"github.com/go-redis/redis/v8"
)

var inviteService *invite.Service
var inviteRepository *invite.Repository

// GetInviteService retrieves an invitation service
func GetInviteService() *invite.Service {
	if inviteService != nil {
		return inviteService
	}

	repo := getInviteRepository()
	inviteService = invite.NewInviteService(*repo)
	return inviteService
}

func getInviteRepository() *invite.Repository {
	if inviteRepository != nil {
		return inviteRepository
	}

	opts := redis.Options{
		Addr: config.Server.Redis.Host,
		DB:   config.Server.Redis.Db,
	}

	repo := invite.NewRedisRepository(&opts)
	inviteRepository = &repo
	return inviteRepository
}
