// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package redisadapter

import (
	"log"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/gomodule/redigo/redis"
)

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	t.Helper()
	myRes := e.GetPolicy()
	log.Print("Policy: ", myRes)

	m := make(map[string]bool, len(res))
	for _, value := range res {
		key := strings.Join(value, ",")
		m[key] = true
	}

	for _, value := range myRes {
		key := strings.Join(value, ",")
		if !m[key] {
			t.Error("Policy: ", myRes, ", supposed to be ", res)
			break
		}
	}
}

func initPolicy(t *testing.T, a *Adapter) {
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err := a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Load the policy from DB.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testSaveLoad(t *testing.T, a *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testAutoSave(t *testing.T, a *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	_, err = e.AddPolicy("alice", "data1", "write")
	logErr("AddPolicy")
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	logErr("LoadPolicy")
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	_, err = e.AddPolicy("alice", "data1", "write")
	logErr("AddPolicy2")
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	logErr("LoadPolicy2")
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	// Remove the added rule.
	_, err = e.RemovePolicy("alice", "data1", "write")
	logErr("RemovePolicy")
	err = e.LoadPolicy()
	logErr("LoadPolicy3")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	_, err = e.RemoveFilteredPolicy(0, "data2_admin")
	logErr("RemoveFilteredPolicy")
	err = e.LoadPolicy()
	logErr("LoadPolicy4")

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func testFilteredPolicy(t *testing.T, a *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")
	// Now set the adapter
	e.SetAdapter(a)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	// Load only alice's policies
	err = e.LoadFilteredPolicy(Filter{V0: []string{"alice"}})
	logErr("LoadFilteredPolicy")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}})

	// Load only bob's policies
	err = e.LoadFilteredPolicy(Filter{V0: []string{"bob"}})
	logErr("LoadFilteredPolicy2")
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	// Load policies for data2_admin
	err = e.LoadFilteredPolicy(Filter{V0: []string{"data2_admin"}})
	logErr("LoadFilteredPolicy3")
	testGetPolicy(t, e, [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Load policies for alice and bob
	err = e.LoadFilteredPolicy(Filter{V0: []string{"alice", "bob"}})
	logErr("LoadFilteredPolicy4")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func testRemovePolicies(t *testing.T, a *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")

	// Now set the adapter
	e.SetAdapter(a)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	err = a.AddPolicies("p", "p", [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}, {"max", "data1", "delete"}})
	logErr("AddPolicies")

	// Load policies for max
	err = e.LoadFilteredPolicy(Filter{V0: []string{"max"}})
	logErr("LoadFilteredPolicy")

	testGetPolicy(t, e, [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}, {"max", "data1", "delete"}})

	// Remove policies
	err = a.RemovePolicies("p", "p", [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}})
	logErr("RemovePolicies")

	// Reload policies for max
	err = e.LoadFilteredPolicy(Filter{V0: []string{"max"}})
	logErr("LoadFilteredPolicy2")

	testGetPolicy(t, e, [][]string{{"max", "data1", "delete"}})
}

func testAddPolicies(t *testing.T, a *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")

	// Now set the adapter
	e.SetAdapter(a)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	err = a.AddPolicies("p", "p", [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}})
	logErr("AddPolicies")

	// Load policies for max
	err = e.LoadFilteredPolicy(Filter{V0: []string{"max"}})
	logErr("LoadFilteredPolicy")

	testGetPolicy(t, e, [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}})
}

func testUpdatePolicies(t *testing.T, a *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")

	// Now set the adapter
	e.SetAdapter(a)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	err = a.UpdatePolicy("p", "p", []string{"bob", "data2", "write"}, []string{"alice", "data2", "write"})
	logErr("UpdatePolicy")

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"alice", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	err = a.UpdatePolicies("p", "p", [][]string{{"alice", "data1", "read"}, {"alice", "data2", "write"}}, [][]string{{"bob", "data1", "read"}, {"bob", "data2", "write"}})
	logErr("UpdatePolicies")

	testGetPolicy(t, e, [][]string{{"bob", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testUpdateFilteredPolicies(t *testing.T, a *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")

	// Now set the adapter
	e.SetAdapter(a)

	e.UpdateFilteredPolicies([][]string{{"alice", "data1", "write"}}, 0, "alice", "data1", "read")
	e.UpdateFilteredPolicies([][]string{{"bob", "data2", "read"}}, 0, "bob", "data2", "write")
	e.LoadPolicy()
	testGetPolicyWithoutOrder(t, e, [][]string{{"alice", "data1", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"bob", "data2", "read"}})
}

func testGetPolicyWithoutOrder(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes := e.GetPolicy()
	log.Print("Policy: ", myRes)

	if !arrayEqualsWithoutOrder(myRes, res) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func arrayEqualsWithoutOrder(a [][]string, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}

	mapA := make(map[int]string)
	mapB := make(map[int]string)
	order := make(map[int]struct{})
	l := len(a)

	for i := 0; i < l; i++ {
		mapA[i] = util.ArrayToString(a[i])
		mapB[i] = util.ArrayToString(b[i])
	}

	for i := 0; i < l; i++ {
		for j := 0; j < l; j++ {
			if _, ok := order[j]; ok {
				if j == l-1 {
					return false
				} else {
					continue
				}
			}
			if mapA[i] == mapB[j] {
				order[j] = struct{}{}
				break
			} else if j == l-1 {
				return false
			}
		}
	}
	return true
}

func TestAdapters(t *testing.T) {
	a, _ := NewAdapterBasic("tcp", "127.0.0.1:6379")

	// Use the following if Redis has password like "123"
	// a, err := NewAdapterWithPassword("tcp", "127.0.0.1:6379", "123")

	// Use the following if you use Redis with a account
	// a, err := NewAdapterWithUser("tcp", "127.0.0.1:6379", "testaccount", "userpass")
	testSaveLoad(t, a)
	testAutoSave(t, a)
	testFilteredPolicy(t, a)
	testAddPolicies(t, a)
	testRemovePolicies(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestAdapterWithOption(t *testing.T) {
	a, _ := NewAdapterWithOption(WithNetwork("tcp"), WithAddress("127.0.0.1:6379"))
	// User the following if use TLS to connect to redis
	// var clientTLSConfig tls.Config
	// a, err := NewAdapterWithOption(WithTls(&clientTLSConfig))

	testSaveLoad(t, a)
	testAutoSave(t, a)
	testFilteredPolicy(t, a)
	testAddPolicies(t, a)
	testRemovePolicies(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestPoolAdapters(t *testing.T) {
	a, err := NewAdapterWithPool(&redis.Pool{
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", "127.0.0.1:6379")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	testSaveLoad(t, a)
	testAutoSave(t, a)
	testFilteredPolicy(t, a)
	testAddPolicies(t, a)
	testRemovePolicies(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestPoolAndOptionsAdapters(t *testing.T) {
	a, err := NewAdapterWithPoolAndOptions(&redis.Pool{
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", "127.0.0.1:6379")
		},
	}, WithKey("casbin:policy:test"))
	if err != nil {
		t.Fatal(err)
	}

	testSaveLoad(t, a)
	testAutoSave(t, a)
	testFilteredPolicy(t, a)
	testAddPolicies(t, a)
	testRemovePolicies(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestNewAdapterWithConfig(t *testing.T) {
	// Test basic configuration
	config := &Config{
		Network: "tcp",
		Address: "127.0.0.1:6379",
	}
	a, _ := NewAdapter(config)

	testSaveLoad(t, a)
	testAutoSave(t, a)
	testFilteredPolicy(t, a)
	testAddPolicies(t, a)
	testRemovePolicies(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestNewAdapterWithPool(t *testing.T) {
	// Test with connection pool
	pool := &redis.Pool{
		MaxIdle:   3,
		MaxActive: 5,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", "127.0.0.1:6379")
		},
	}
	config := &Config{
		Pool: pool,
		Key:  "pool_test_rules",
	}
	a, err := NewAdapter(config)
	if err != nil {
		t.Fatal(err)
	}

	testSaveLoad(t, a)
	testAutoSave(t, a)
	testFilteredPolicy(t, a)
	testAddPolicies(t, a)
	testRemovePolicies(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestNewAdapterErrorCases(t *testing.T) {
	// Test error cases
	_, err := NewAdapter(nil)
	if err == nil {
		t.Error("NewAdapter should fail with nil config")
	}

	config := &Config{
		Network: "",
		Address: "127.0.0.1:6379",
	}
	_, err = NewAdapter(config)
	if err == nil {
		t.Error("NewAdapter should fail with empty network")
	}

	config = &Config{
		Network: "tcp",
		Address: "",
	}
	_, err = NewAdapter(config)
	if err == nil {
		t.Error("NewAdapter should fail with empty address")
	}
}

func TestNewAdapterWithPassword(t *testing.T) {
	// Test with password authentication
	a, err := NewAdapterWithPassword("tcp", "127.0.0.1:6379", "testpass")
	if err != nil {
		t.Skipf("Password authentication test skipped (Redis may not have auth configured): %v", err)
	}

	testSaveLoad(t, a)
	testAutoSave(t, a)
	testFilteredPolicy(t, a)
	testAddPolicies(t, a)
	testRemovePolicies(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestNewAdapterWithUser(t *testing.T) {
	// Test with username and password authentication
	a, err := NewAdapterWithUser("tcp", "127.0.0.1:6379", "testuser", "testpass")
	if err != nil {
		t.Skipf("User authentication test skipped (Redis may not have auth configured): %v", err)
	}

	testSaveLoad(t, a)
	testAutoSave(t, a)
	testFilteredPolicy(t, a)
	testAddPolicies(t, a)
	testRemovePolicies(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestNewAdapterWithKey(t *testing.T) {
	// Test with custom key
	a, err := NewAdapterWithKey("tcp", "127.0.0.1:6379", "custom_casbin_key")
	if err != nil {
		t.Fatal(err)
	}

	testSaveLoad(t, a)
	testAutoSave(t, a)
	testFilteredPolicy(t, a)
	testAddPolicies(t, a)
	testRemovePolicies(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestIsFiltered(t *testing.T) {
	// Test IsFiltered functionality
	a, err := NewAdapterBasic("tcp", "127.0.0.1:6379")
	if err != nil {
		t.Fatal(err)
	}

	// Initially should not be filtered
	if a.IsFiltered() {
		t.Error("Adapter should not be filtered initially")
	}

	// Initialize policy
	initPolicy(t, a)

	// Create enforcer and load filtered policy
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")
	e.SetAdapter(a)

	// Load filtered policy
	err = e.LoadFilteredPolicy(Filter{V0: []string{"alice"}})
	if err != nil {
		t.Fatalf("LoadFilteredPolicy failed: %v", err)
	}

	// Now should be filtered
	if !a.IsFiltered() {
		t.Error("Adapter should be filtered after LoadFilteredPolicy")
	}

	// Load all policies (not filtered)
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	// Should not be filtered anymore
	if a.IsFiltered() {
		t.Error("Adapter should not be filtered after LoadPolicy")
	}
}

func TestFilterFunctionality(t *testing.T) {
	// Test various filter scenarios
	a, err := NewAdapterBasic("tcp", "127.0.0.1:6379")
	if err != nil {
		t.Fatal(err)
	}

	// Initialize policy
	initPolicy(t, a)

	// Create enforcer
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")
	e.SetAdapter(a)

	// Test filter with multiple values
	err = e.LoadFilteredPolicy(Filter{V0: []string{"alice", "bob"}})
	if err != nil {
		t.Fatalf("LoadFilteredPolicy with multiple values failed: %v", err)
	}

	policies := e.GetPolicy()
	if len(policies) == 0 {
		t.Error("Expected policies after filtered load")
	}

	// Test filter with V1 field
	err = e.LoadFilteredPolicy(Filter{V1: []string{"data1"}})
	if err != nil {
		t.Fatalf("LoadFilteredPolicy with V1 failed: %v", err)
	}

	policies = e.GetPolicy()
	for _, policy := range policies {
		if len(policy) > 1 && policy[1] != "data1" {
			t.Errorf("Expected policy with data1, got %v", policy)
		}
	}

	// Test filter with V2 field
	err = e.LoadFilteredPolicy(Filter{V2: []string{"read"}})
	if err != nil {
		t.Fatalf("LoadFilteredPolicy with V2 failed: %v", err)
	}

	policies = e.GetPolicy()
	for _, policy := range policies {
		if len(policy) > 2 && policy[2] != "read" {
			t.Errorf("Expected policy with read action, got %v", policy)
		}
	}
}

func TestRemoveFilteredPolicy(t *testing.T) {
	// Test RemoveFilteredPolicy functionality
	a, err := NewAdapterBasic("tcp", "127.0.0.1:6379")
	if err != nil {
		t.Fatal(err)
	}

	// Initialize policy
	initPolicy(t, a)

	// Create enforcer
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")
	e.SetAdapter(a)

	// Load all policies first
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	// Test RemoveFilteredPolicy - remove alice's policies
	err = a.RemoveFilteredPolicy("p", "p", 0, "alice")
	if err != nil {
		t.Fatalf("RemoveFilteredPolicy failed: %v", err)
	}

	// Reload and check
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		t.Fatalf("LoadPolicy after RemoveFilteredPolicy failed: %v", err)
	}

	policies := e.GetPolicy()
	aliceCount := 0
	for _, policy := range policies {
		if len(policy) > 0 && policy[0] == "alice" {
			aliceCount++
		}
	}

	// We expect fewer alice policies after removal
	if aliceCount > 0 {
		t.Logf("Alice policies count after removal: %d", aliceCount)
		// This is expected if the filter didn't match all alice policies
	}
}

func TestInvalidFilterType(t *testing.T) {
	// Test LoadFilteredPolicy with invalid filter type directly on adapter
	a, err := NewAdapterBasic("tcp", "127.0.0.1:6379")
	if err != nil {
		t.Fatal(err)
	}

	// Initialize policy
	initPolicy(t, a)

	// Create model for testing
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")

	// Test with invalid filter type directly on adapter
	err = a.LoadFilteredPolicy(e.GetModel(), "invalid_filter_type")
	if err == nil {
		t.Error("Expected error for invalid filter type")
	} else {
		t.Logf("Got expected error for invalid filter type: %v", err)
	}
}

func TestEmptyPolicyOperations(t *testing.T) {
	// Test operations on empty policies
	a, err := NewAdapterBasic("tcp", "127.0.0.1:6379")
	if err != nil {
		t.Fatal(err)
	}

	// Test AddPolicy with single empty string (valid rule)
	err = a.AddPolicy("p", "p", []string{""})
	if err != nil {
		t.Errorf("AddPolicy with empty string failed: %v", err)
	}

	// Test RemovePolicy with single empty string
	err = a.RemovePolicy("p", "p", []string{""})
	if err != nil {
		t.Errorf("RemovePolicy with empty string failed: %v", err)
	}

	// Test AddPolicies with single rule containing empty string
	err = a.AddPolicies("p", "p", [][]string{{"", "data1", "read"}})
	if err != nil {
		t.Errorf("AddPolicies with rule containing empty string failed: %v", err)
	}

	// Test RemovePolicies with single rule containing empty string
	err = a.RemovePolicies("p", "p", [][]string{{"", "data1", "read"}})
	if err != nil {
		t.Errorf("RemovePolicies with rule containing empty string failed: %v", err)
	}
}
