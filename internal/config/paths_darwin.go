//go:build darwin

package config

const stateDirPath = "/Library/Application Support/vpnsplit"

func secureStateDir(create bool) (string, error) { return secureDirUnix(stateDirPath, create, 0) }
