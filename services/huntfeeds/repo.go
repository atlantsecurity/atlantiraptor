package huntfeeds

import (
	"context"
	"fmt"
	"strings"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/services"
)

// FeedTag is the repository tag on every feed artifact.
const FeedTag = "Atlant feed"

// repositoryInstaller loads feed artifacts into the root org's artifact
// repository, which every org's repository inherits from. They are
// loaded as built in: the console shows them read-only and nobody can
// save over them.
type repositoryInstaller struct {
	config_obj *config_proto.Config
}

type forceDeleter interface {
	ForceDel(name string)
}

func (self *repositoryInstaller) Install(definition string) (string, error) {
	manager, err := services.GetRepositoryManager(self.config_obj)
	if err != nil {
		return "", err
	}
	global, err := manager.GetGlobalRepository(self.config_obj)
	if err != nil {
		return "", err
	}

	// Validate in a scratch repository first.
	scratch := manager.NewRepository()
	art, err := scratch.LoadYaml(definition, services.ArtifactOptions{ValidateArtifact: true})
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(art.Name, ArtifactPrefix) {
		return "", fmt.Errorf("artifact %v is not named %v*", art.Name, ArtifactPrefix)
	}
	if art.Type != "client" {
		return "", fmt.Errorf("artifact %v is of type %v; feeds only deliver client artifacts",
			art.Name, art.Type)
	}
	// Never replace a customer's own artifact that happens to use the prefix.
	if existing, ok := global.Get(context.Background(), self.config_obj, art.Name); ok &&
		!existing.BuiltIn {
		return "", fmt.Errorf("a custom artifact called %v already exists on this server", art.Name)
	}

	_, err = global.LoadYaml(definition, services.ArtifactOptions{
		ValidateArtifact:  true,
		ArtifactIsBuiltIn: true,
		Tags:              []string{FeedTag},
	})
	if err != nil {
		return "", err
	}
	return art.Name, nil
}

func (self *repositoryInstaller) Remove(name string) {
	if !strings.HasPrefix(name, ArtifactPrefix) {
		return
	}
	manager, err := services.GetRepositoryManager(self.config_obj)
	if err != nil {
		return
	}
	global, err := manager.GetGlobalRepository(self.config_obj)
	if err != nil {
		return
	}
	if d, ok := global.(forceDeleter); ok {
		d.ForceDel(name)
	} else {
		global.Del(name)
	}
}
