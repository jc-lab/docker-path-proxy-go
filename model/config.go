package model

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
)

type Registry struct {
	Path            string `yaml:"path"`
	Endpoint        string `yaml:"endpoint"`
	SkipVerify      bool   `yaml:"skipVerify"`
	Username        string `yaml:"username"`
	Password        string `yaml:"password"`
	PasswordRefFile string `yaml:"passwordRefFile"`
	PasswordRefEnv  string `yaml:"passwordRefEnv"`
}

type DefaultBackend struct {
	Disabled bool `yaml:"disabled"`
}

type Config struct {
	DefaultBackend DefaultBackend `yaml:"defaultBackend"`
	Registries     []*Registry    `yaml:"registries"`
	CaCertificates []string       `yaml:"caCertificates"`
}

func ReadConfig(content []byte) (*Config, error) {
	config := &Config{}
	if err := yaml.Unmarshal(content, config); err != nil {
		return nil, err
	}

	for _, registry := range config.Registries {
		if registry.PasswordRefFile != "" {
			raw, err := os.ReadFile(registry.PasswordRefFile)
			if err != nil {
				return nil, fmt.Errorf("password file \"%s\" read failed: %v", registry.PasswordRefFile, err)
			}
			registry.Password = string(raw)
		} else if registry.PasswordRefEnv != "" {
			registry.Password = os.Getenv(registry.PasswordRefEnv)
		}
	}

	return config, nil
}
