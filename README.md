Redis Adapter
====

[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/redis-adapter)](https://goreportcard.com/report/github.com/casbin/redis-adapter)
[![Build](https://github.com/casbin/redis-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/casbin/redis-adapter/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/casbin/redis-adapter/badge.svg?branch=master)](https://coveralls.io/github/casbin/redis-adapter?branch=master)
[![Godoc](https://godoc.org/github.com/casbin/redis-adapter?status.svg)](https://pkg.go.dev/github.com/casbin/redis-adapter/v3)
[![Release](https://img.shields.io/github/release/casbin/redis-adapter.svg)](https://github.com/casbin/redis-adapter/releases/latest)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)
[![Sourcegraph](https://sourcegraph.com/github.com/casbin/redis-adapter/-/badge.svg)](https://sourcegraph.com/github.com/casbin/redis-adapter?badge)

Redis Adapter is the [Redis](https://redis.io/) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from Redis or save policy to it.

## Installation

    go get github.com/casbin/redis-adapter/v3

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/redis-adapter/v3"
)

func main() {
	// Basic initialization (deprecated)
	a, _ := redisadapter.NewAdapterBasic("tcp", "127.0.0.1:6379")

	// With password (deprecated)
	// a, err := redisadapter.NewAdapterWithPassword("tcp", "127.0.0.1:6379", "123")

	// With user credentials (deprecated)
	// a, err := redisadapter.NewAdapterWithUser("tcp", "127.0.0.1:6379", "username", "password")

	// With custom key (deprecated)
	// a, err := redisadapter.NewAdapterWithKey("tcp", "127.0.0.1:6379", "my_rules")

	// With connection pool (deprecated)
	// pool := &redis.Pool{}
	// a, err := redisadapter.NewAdapterWithPool(pool)

	// With options pattern (deprecated)
	// a, err := redisadapter.NewAdapterWithOption(
	//     redisadapter.WithNetwork("tcp"),
	//     redisadapter.WithAddress("127.0.0.1:6379"),
	//     redisadapter.WithPassword("123"),
	//     redisadapter.WithKey("my_rules"),
	// )

	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	// Load the policy from DB.
	e.LoadPolicy()

	// Check the permission.
	e.Enforce("alice", "data1", "read")

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	e.SavePolicy()
}
```

## Configuration Options

The `Config` struct supports the following options:

- `Network` (string): Network type, e.g., "tcp", "unix" (required when not using Pool)
- `Address` (string): Redis server address, e.g., "127.0.0.1:6379" (required when not using Pool)
- `Key` (string): Redis key to store Casbin rules (default: "casbin_rules")
- `Username` (string): Username for Redis authentication (optional)
- `Password` (string): Password for Redis authentication (optional)
- `TLSConfig` (*tls.Config): TLS configuration for secure connections (optional)
- `Pool` (*redis.Pool): Existing Redis connection pool (optional, if provided, other connection options are ignored)

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
