package limb

import (
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/store"
)

type actorRef struct {
	actor audit.Actor
	ip    string
}

var apiActor = actorRef{actor: audit.API}

func (r actorRef) adminID() string {
	if r.actor.Kind == store.ActorAdmin {
		return r.actor.ID
	}
	return ""
}

func adminActor(id string) audit.Actor {
	return audit.Actor{Kind: store.ActorAdmin, ID: id}
}
