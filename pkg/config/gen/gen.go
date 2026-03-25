package main

import (
	cfg "github.com/conductorone/baton-kubernetes/pkg/config"
	sdkconfig "github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	sdkconfig.Generate("kubernetes", cfg.Configuration)
}
