package config

import (
	"github.com/BurntSushi/toml"
)

type Config struct {
	Slack   SlackConf
	Trivy   TrivyConf
	Fluentd FluentdConf
}

type SlackConf struct {
	HookURL     string   `valid:"url" json:"-" toml:"hookURL,omitempty"`
	Token       string   `json:"-" toml:"token,omitempty"`
	Channel     string   `json:"-" toml:"channel,omitempty"`
	IconEmoji   string   `json:"-" toml:"iconEmoji,omitempty"`
	AuthUser    string   `json:"-" toml:"authUser,omitempty"`
	NotifyUsers []string `toml:"notifyUsers,omitempty" json:"-"`
	Text        string   `json:"-"`
}

type TrivyConf struct {
	Format        string `toml:"format,omitempty"`
	Severity      string `toml:"serverity,omitempty"`
	CacheDir      string `toml:"cacheDir,omitempty"`
	SkipUpdate    bool   `toml:"skipUpdate,omitempty"`
	OnlyUpdate    bool   `toml:"onlyUpdate,omitempty"`
	Reset         bool   `toml:"reset,omitempty"`
	ClearCache    bool   `toml:"clearCache,omitempty"`
	Quiet         bool   `toml:"quiet,omitempty"`
	IgnoreUnfixed bool   `toml:"ignoreUnfixed,omitempty"`
	Refresh       bool   `toml:"refresh,omitempty"`
	AutoRefresh   bool   `toml:"autoRefresh,omitempty"`
	Debug         bool   `toml:"debug,omitempty"`
	Slack         bool   `toml:"slack,omitempty"`
}

type FluentdConf struct {
}

func Load(pathToToml string) (*Config, error) {
	var conf Config
	if _, err := toml.DecodeFile(pathToToml, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
}
