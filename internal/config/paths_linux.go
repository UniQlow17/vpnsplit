//go:build linux

package config

const stateDirPath = "/var/lib/vpnsplit"

func secureStateDir(create bool) (string, error) { return secureDirUnix(stateDirPath, create, 0) }
