//go:build linux

package jail

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

func readConfig(fd int) (InitConfig, error) {
	f := os.NewFile(uintptr(fd), "config")
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return InitConfig{}, fmt.Errorf("jail: read config: %w", err)
	}
	var cfg InitConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return InitConfig{}, fmt.Errorf("jail: parse config: %w", err)
	}
	if len(cfg.Args) == 0 {
		return InitConfig{}, errors.New("jail: config has no prisoner command")
	}
	return cfg, nil
}
