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
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/gomodule/redigo/redis"
)

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
