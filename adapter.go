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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gomodule/redigo/redis"
)

// CasbinRule is used to determine which policy line to load.
type CasbinRule struct {
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// Config represents the configuration for the Redis adapter.
type Config struct {
	// Network is the network type, e.g., "tcp", "unix"
	Network string
	// Address is the Redis server address, e.g., "127.0.0.1:6379"
	Address string
	// Key is the Redis key to store Casbin rules (default: "casbin_rules")
	Key string
	// Username for Redis authentication (optional)
	Username string
	// Password for Redis authentication (optional)
	Password string
	// TLSConfig for secure connections (optional)
	TLSConfig *tls.Config
	// Pool is an existing Redis connection pool (optional)
	// If provided, Network, Address, Username, Password, and TLSConfig are ignored
	Pool *redis.Pool
}

// Adapter represents the Redis adapter for policy storage.
type Adapter struct {
	network    string
	address    string
	key        string
	username   string
	password   string
	tlsConfig  *tls.Config
	_conn      redis.Conn
	_pool      *redis.Pool
	isFiltered bool
}

func (a *Adapter) getConn() redis.Conn {
	if a._pool != nil {
		return a._pool.Get()
	}
	return a._conn
}

func (a *Adapter) release(conn redis.Conn) {
	if a._pool != nil {
		if conn != nil {
			conn.Close()
		}
	}
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {
	if a._conn != nil {
		a._conn.Close()
	}
	if a._pool != nil {
		a._pool.Close()
	}
}

// NewAdapter creates a new Redis adapter with the provided configuration.
func NewAdapter(config *Config) (*Adapter, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	a := &Adapter{}

	// Set default key if not provided
	if config.Key == "" {
		a.key = "casbin_rules"
	} else {
		a.key = config.Key
	}

	// If a pool is provided, use it
	if config.Pool != nil {
		a._pool = config.Pool
	} else {
		// Otherwise, create a new connection
		if config.Network == "" {
			return nil, errors.New("network is required when not using a pool")
		}
		if config.Address == "" {
			return nil, errors.New("address is required when not using a pool")
		}

		a.network = config.Network
		a.address = config.Address
		a.username = config.Username
		a.password = config.Password
		a.tlsConfig = config.TLSConfig

		// Open the DB connection
		err := a.open()
		if err != nil {
			return nil, err
		}
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

// Legacy constructor functions (deprecated)
// These are kept for backward compatibility but should be avoided in new code

// NewAdapterBasic is the basic constructor for Adapter.
// Deprecated: Use NewAdapter with Config struct instead.
func NewAdapterBasic(network string, address string) (*Adapter, error) {
	config := &Config{
		Network: network,
		Address: address,
	}
	return NewAdapter(config)
}

// NewAdapterWithUser creates adapter with user credentials.
// Deprecated: Use NewAdapter with Config struct instead.
func NewAdapterWithUser(network string, address string, username string, password string) (*Adapter, error) {
	config := &Config{
		Network:  network,
		Address:  address,
		Username: username,
		Password: password,
	}
	return NewAdapter(config)
}

// NewAdapterWithPassword creates adapter with password authentication.
// Deprecated: Use NewAdapter with Config struct instead.
func NewAdapterWithPassword(network string, address string, password string) (*Adapter, error) {
	config := &Config{
		Network:  network,
		Address:  address,
		Password: password,
	}
	return NewAdapter(config)
}

// NewAdapterWithKey creates adapter with custom key.
// Deprecated: Use NewAdapter with Config struct instead.
func NewAdapterWithKey(network string, address string, key string) (*Adapter, error) {
	config := &Config{
		Network: network,
		Address: address,
		Key:     key,
	}
	return NewAdapter(config)
}

// NewAdapterWithPool creates adapter with connection pool.
// Deprecated: Use NewAdapter with Config struct instead.
func NewAdapterWithPool(pool *redis.Pool) (*Adapter, error) {
	config := &Config{
		Pool: pool,
	}
	return NewAdapter(config)
}

// NewAdapterWithPoolAndOptions creates adapter with pool and options.
// Deprecated: Use NewAdapter with Config struct instead.
func NewAdapterWithPoolAndOptions(pool *redis.Pool, options ...Option) (*Adapter, error) {
	config := &Config{
		Pool: pool,
	}
	a, err := NewAdapter(config)
	if err != nil {
		return nil, err
	}

	// Apply options for backward compatibility
	for _, option := range options {
		option(a)
	}

	return a, nil
}

type Option func(*Adapter)

// NewAdapterWithOption creates adapter with options pattern.
// Deprecated: Use NewAdapter with Config struct instead.
func NewAdapterWithOption(options ...Option) (*Adapter, error) {
	a := &Adapter{}
	for _, option := range options {
		option(a)
	}

	// Convert to new config-based approach
	config := &Config{
		Network:   a.network,
		Address:   a.address,
		Key:       a.key,
		Username:  a.username,
		Password:  a.password,
		TLSConfig: a.tlsConfig,
	}

	return NewAdapter(config)
}

func WithAddress(address string) Option {
	return func(a *Adapter) {
		a.address = address
	}
}

func WithUsername(username string) Option {
	return func(a *Adapter) {
		a.username = username
	}
}

func WithPassword(password string) Option {
	return func(a *Adapter) {
		a.password = password
	}
}

func WithNetwork(network string) Option {
	return func(a *Adapter) {
		a.network = network
	}
}

func WithKey(key string) Option {
	return func(a *Adapter) {
		a.key = key
	}
}

func WithTls(tlsConfig *tls.Config) Option {
	return func(a *Adapter) {
		a.tlsConfig = tlsConfig
	}
}

func (a *Adapter) open() error {
	//redis.Dial("tcp", "127.0.0.1:6379")
	useTls := a.tlsConfig != nil
	if a.username != "" {
		conn, err := redis.Dial(a.network, a.address, redis.DialUsername(a.username), redis.DialPassword(a.password), redis.DialTLSConfig(a.tlsConfig), redis.DialUseTLS(useTls))
		if err != nil {
			return err
		}

		a._conn = conn
	} else if a.password == "" {
		conn, err := redis.Dial(a.network, a.address, redis.DialTLSConfig(a.tlsConfig), redis.DialUseTLS(useTls))
		if err != nil {
			return err
		}

		a._conn = conn
	} else {
		conn, err := redis.Dial(a.network, a.address, redis.DialPassword(a.password), redis.DialTLSConfig(a.tlsConfig), redis.DialUseTLS(useTls))
		if err != nil {
			return err
		}

		a._conn = conn
	}
	return nil
}

func (a *Adapter) close() {
	if a._conn != nil {
		a._conn.Close()
	}
	if a._pool != nil {
		a._pool.Close()
	}
}

func (a *Adapter) createTable() {
}

func (a *Adapter) dropTable() {
	conn := a.getConn()
	defer a.release(conn)

	_, _ = conn.Do("DEL", a.key)
}

func (c *CasbinRule) toStringPolicy() []string {
	policy := make([]string, 0)
	if c.PType != "" {
		policy = append(policy, c.PType)
	}
	if c.V0 != "" {
		policy = append(policy, c.V0)
	}
	if c.V1 != "" {
		policy = append(policy, c.V1)
	}
	if c.V2 != "" {
		policy = append(policy, c.V2)
	}
	if c.V3 != "" {
		policy = append(policy, c.V3)
	}
	if c.V4 != "" {
		policy = append(policy, c.V4)
	}
	if c.V5 != "" {
		policy = append(policy, c.V5)
	}
	return policy
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	text := line.toStringPolicy()

	persist.LoadPolicyArray(text, model)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	conn := a.getConn()
	defer a.release(conn)

	num, err := redis.Int(conn.Do("LLEN", a.key))
	if err == redis.ErrNil {
		return nil
	}
	if err != nil {
		return err
	}
	values, err := redis.Values(conn.Do("LRANGE", a.key, 0, num))
	if err != nil {
		return err
	}

	var line CasbinRule
	for _, value := range values {
		text, ok := value.([]byte)
		if !ok {
			// Amazon MemoryDB for Redis returns string instead of []byte
			if textStr, ok := value.(string); ok {
				text = []byte(textStr)
			} else {
				return errors.New("the type is wrong")
			}
		}
		err = json.Unmarshal(text, &line)
		if err != nil {
			return err
		}
		loadPolicyLine(line, model)
	}

	a.isFiltered = false
	return nil
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{}

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	a.dropTable()
	a.createTable()

	var texts [][]byte

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			text, err := json.Marshal(line)
			if err != nil {
				return err
			}
			texts = append(texts, text)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			text, err := json.Marshal(line)
			if err != nil {
				return err
			}
			texts = append(texts, text)
		}
	}

	conn := a.getConn()
	defer a.release(conn)

	_, err := conn.Do("RPUSH", redis.Args{}.Add(a.key).AddFlat(texts)...)
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	text, err := json.Marshal(line)
	if err != nil {
		return err
	}

	conn := a.getConn()
	defer a.release(conn)

	_, err = conn.Do("RPUSH", a.key, text)
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	text, err := json.Marshal(line)
	if err != nil {
		return err
	}

	conn := a.getConn()
	defer a.release(conn)

	_, err = conn.Do("LREM", a.key, 1, text)
	return err
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var texts [][]byte
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		text, err := json.Marshal(line)
		if err != nil {
			return err
		}
		texts = append(texts, text)
	}

	conn := a.getConn()
	defer a.release(conn)

	_, err := conn.Do("RPUSH", redis.Args{}.Add(a.key).AddFlat(texts)...)
	return err
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	conn := a.getConn()
	defer a.release(conn)

	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		text, err := json.Marshal(line)
		if err != nil {
			return err
		}
		_, err = conn.Do("LREM", a.key, 1, text)
		if err != nil {
			return err
		}
	}
	return nil
}

//FilteredAdapter

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

type Filter struct {
	PType []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

func filterToRegexPattern(filter *Filter) string {
	// example data in redis: {"PType":"p","V0":"data2_admin","V1":"data2","V2":"write","V3":"","V4":"","V5":""}

	var f = [][]string{filter.PType,
		filter.V0, filter.V1, filter.V2,
		filter.V3, filter.V4, filter.V5}

	args := []interface{}{}
	for _, v := range f {
		if len(v) == 0 {
			args = append(args, ".*")
		} else {
			escapedV := make([]string, 0, len(v))
			for _, s := range v {
				escapedV = append(escapedV, regexp.QuoteMeta(s))
			}
			args = append(args, "(?:"+strings.Join(escapedV, "|")+")") // (?:data2_admin|data1_admin)
		}
	}

	// example pattern:
	//^\{"PType":".*","V0":"(?:data2_admin|data1_admin)","V1":".*","V2":".*","V3":".*","V4":".*","V5":".*"\}$
	pattern := fmt.Sprintf(
		`^\{"PType":"%s","V0":"%s","V1":"%s","V2":"%s","V3":"%s","V4":"%s","V5":"%s"\}$`, args...,
	)
	return pattern
}

func escapeLuaPattern(s string) string {
	var buf bytes.Buffer
	for _, char := range s {
		switch char {
		case '.', '%', '-', '+', '*', '?', '^', '$', '(', ')', '[', ']': // magic chars: . % + - * ? [ ( ) ^ $
			buf.WriteRune('%')
		}
		buf.WriteRune(char)
	}
	return buf.String()
}

func filterFieldToLuaPattern(sec string, ptype string, fieldIndex int, fieldValues ...string) string {
	args := []interface{}{ptype}

	idx := fieldIndex + len(fieldValues)
	for i := 0; i < 6; i++ { // v0-v5
		if fieldIndex <= i && idx > i && fieldValues[i-fieldIndex] != "" {
			args = append(args, escapeLuaPattern(fieldValues[i-fieldIndex]))
		} else {
			args = append(args, ".*")
		}
	}

	// example pattern:
	// ^{"PType":"p","V0":"data2_admin","V1":".*","V2":".*","V3":".*","V4":".*","V5":".*"}$
	pattern := fmt.Sprintf(
		`^{"PType":"%s","V0":"%s","V1":"%s","V2":"%s","V3":"%s","V4":"%s","V5":"%s"}$`, args...,
	)
	return pattern
}

func (a *Adapter) loadFilteredPolicy(model model.Model, filter *Filter) error {
	conn := a.getConn()
	defer a.release(conn)

	num, err := redis.Int(conn.Do("LLEN", a.key))
	if err == redis.ErrNil {
		return nil
	}
	if err != nil {
		return err
	}
	values, err := redis.Values(conn.Do("LRANGE", a.key, 0, num))
	if err != nil {
		return err
	}

	re := regexp.MustCompile(filterToRegexPattern(filter))

	var line CasbinRule
	for _, value := range values {
		text, ok := value.([]byte)
		if !ok {
			// Amazon MemoryDB for Redis returns string instead of []byte
			if textStr, ok := value.(string); ok {
				text = []byte(textStr)
			} else {
				return errors.New("the type is wrong")
			}
		}

		if !re.Match(text) {
			continue
		}

		err = json.Unmarshal(text, &line)
		if err != nil {
			return err
		}
		loadPolicyLine(line, model)
	}
	return nil
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicy(model)
	}

	var err error
	switch f := filter.(type) {
	case *Filter:
		err = a.loadFilteredPolicy(model, f)
	case Filter:
		err = a.loadFilteredPolicy(model, &f)
	default:
		err = fmt.Errorf("invalid filter type")
	}

	if err != nil {
		return err
	}
	a.isFiltered = true
	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {

	pattern := filterFieldToLuaPattern(sec, ptype, fieldIndex, fieldValues...)

	var getScript = redis.NewScript(1, `
		local key = KEYS[1]
		local pattern = ARGV[1]
		
		local r = redis.call('lrange', key, 0, -1)
		for i=1, #r do 
			if  string.find(r[i], pattern) then
				redis.call('lset', key, i-1, '__CASBIN_DELETED__')
			end
		end
		redis.call('lrem', key, 0, '__CASBIN_DELETED__')
		return 
	`)

	conn := a.getConn()
	defer a.release(conn)

	_, err := getScript.Do(conn, a.key, pattern)
	return err
}

// UpdatableAdapter

// UpdatePolicy updates a new policy rule to DB.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	oldLine := savePolicyLine(ptype, oldRule)
	textOld, err := json.Marshal(oldLine)
	if err != nil {
		return err
	}
	newLine := savePolicyLine(ptype, newPolicy)
	textNew, err := json.Marshal(newLine)
	if err != nil {
		return err
	}

	var getScript = redis.NewScript(1, `
		local key = KEYS[1]
		local old = ARGV[1]
		local newRule = ARGV[2]
	
		local r = redis.call('lrange', key, 0, -1)
		for i=1,#r do
			if r[i] == old then
				redis.call('lset', key, i-1, newRule)
				return true
			end
		end
		return false
	`)

	conn := a.getConn()
	defer a.release(conn)

	_, err = getScript.Do(conn, a.key, textOld, textNew)
	return err
}

func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {

	if len(oldRules) != len(newRules) {
		return errors.New("oldRules and newRules should have the same length")
	}

	oldPolicies := make([]string, 0, len(oldRules))
	newPolicies := make([]string, 0, len(newRules))
	for _, oldRule := range oldRules {
		textOld, err := json.Marshal(savePolicyLine(ptype, oldRule))
		if err != nil {
			return err
		}
		oldPolicies = append(oldPolicies, string(textOld))
	}
	for _, newRule := range newRules {
		textNew, err := json.Marshal(savePolicyLine(ptype, newRule))
		if err != nil {
			return err
		}
		newPolicies = append(newPolicies, string(textNew))
	}

	// Initialize a package-level variable with a script.
	var getScript = redis.NewScript(1, `
		local key = KEYS[1]
		local len = #ARGV/2
		
		local map = {}
		for i = 1, len, 1 do
			map[ARGV[i]] = ARGV[i + len] -- map[oldRule] = newRule
		end
		
		local r = redis.call('lrange', key, 0, -1)
		for i=1,#r do
			if map[r[i]] ~= nil then
				redis.call('lset', key, i-1, map[r[i]])
				-- return true
			end
		end
		
		return false
	`)
	args := redis.Args{}.Add(a.key).AddFlat(oldPolicies).AddFlat(newPolicies)

	conn := a.getConn()
	defer a.release(conn)

	_, err := getScript.Do(conn, args...)
	return err
}

func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	// UpdateFilteredPolicies deletes old rules and adds new rules.

	oldP := make([]string, 0)
	newP := make([]string, 0, len(newPolicies))
	for _, newRule := range newPolicies {
		textNew, err := json.Marshal(savePolicyLine(ptype, newRule))
		if err != nil {
			return nil, err
		}
		newP = append(newP, string(textNew))
	}

	pattern := filterFieldToLuaPattern(sec, ptype, fieldIndex, fieldValues...)

	// Initialize a package-level variable with a script.
	var getScript = redis.NewScript(1, `
		local key = KEYS[1]
		local pattern = ARGV[1]
		
		local ret = {}
		local r = redis.call('lrange', key, 0, -1)
		for i=1, #r do 
			if  string.find(r[i], pattern) then
        		table.insert(ret, r[i])
				redis.call('lset', key, i-1, '__CASBIN_DELETED__')
			end
		end
		redis.call('lrem', key, 0, '__CASBIN_DELETED__')
		
		local r = redis.call('lrange', key, 0, -1)
		for i=2,#r do
			redis.call('rpush', key, ARGV[i])
		end
		
		return ret
	`)
	args := redis.Args{}.Add(a.key).Add(pattern).AddFlat(newP)
	//r, err := getScript.Do(a.conn, args...)
	//reply, err := redis.Values(r, err)

	conn := a.getConn()
	defer a.release(conn)

	reply, err := redis.Values(getScript.Do(conn, args...))
	if err != nil {
		return nil, err
	}

	if err = redis.ScanSlice(reply, &oldP); err != nil {
		return nil, err
	}

	ret := make([][]string, 0, len(oldP))
	for _, oldRule := range oldP {
		var line CasbinRule
		if err := json.Unmarshal([]byte(oldRule), &line); err != nil {
			return nil, err
		}

		ret = append(ret, line.toStringPolicy())
	}

	return ret, nil
}
