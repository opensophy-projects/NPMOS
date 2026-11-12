package eventconsumer

import (
	"context"
)

func NewDockerAdapter() *DockerAdapter {
	return &DockerAdapter{}
}

type DockerAdapter struct{}

func (*DockerAdapter) Start(ctx context.Context) {
}

func (*DockerAdapter) Stop(ctx context.Context) error {
	return nil
}

func (*DockerAdapter) HealthCheck(ctx context.Context) (string, error) {
	return "", nil
}
