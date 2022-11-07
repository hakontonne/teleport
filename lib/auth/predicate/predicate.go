/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package predicate

import (
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"github.com/vulcand/predicate"
)

type AccessDecision int

const (
	AccessUndecided AccessDecision = iota
	AccessAllowed
	AccessDenied
)

// NamedParameter is an object with a name that can be added to the environment in which a predicate expression runs.
type NamedParameter interface {
	// GetName returns the name of the object.
	GetName() string
}

func buildEnv(objects ...NamedParameter) map[string]any {
	env := make(map[string]any)
	for _, obj := range objects {
		env[obj.GetName()] = obj
	}

	return env
}

func newParser(env map[string]any) (predicate.Parser, error) {
	getIdentifierInEnv := func(selector []string) (any, error) {
		return getIdentifier(env, selector)
	}

	return predicate.NewParser(predicate.Def{
		Operators: predicate.Operators{
			AND: builtinOpAnd,
			OR:  builtinOpOr,
			NOT: builtinOpNot,
			EQ:  builtinOpEquals,
			LT:  builtinOpLT,
			GT:  builtinOpGT,
			LE:  builtinOpLE,
			GE:  builtinOpGE,
		},
		Functions: map[string]any{
			"add":            builtinAdd,
			"sub":            builtinSub,
			"mul":            builtinMul,
			"div":            builtinDiv,
			"xor":            builtinXor,
			"split":          builtinSplit,
			"upper":          builtinUpper,
			"lower":          builtinLower,
			"contains":       builtinContains,
			"first":          builtinFirst,
			"append":         builtinAppend,
			"array":          builtinArray,
			"replace":        builtinReplace,
			"len":            builtinLen,
			"regex":          builtinRegex,
			"matches":        builtinMatches,
			"contains_regex": builtinContainsRegex,
			"map_insert":     builtinMapInsert,
			"map_remove":     builtinMapRemove,
		},
		GetIdentifier: getIdentifierInEnv,
		GetProperty:   getProperty,
	})
}

// PredicateAccessChecker checks access/permissions to access certain resources by evaluating AccessPolicy resources.
type PredicateAccessChecker struct {
	policies []types.AccessPolicy
}

// NewPredicateAccessChecker creates a new PredicateAccessChecker with a set of policies describing the permissions.
func NewPredicateAccessChecker(policies []types.AccessPolicy) *PredicateAccessChecker {
	return &PredicateAccessChecker{policies}
}

// CheckAccessToNode checks if a given user has login access to a Server Access node.
func (c *PredicateAccessChecker) CheckLoginAccessToNode(node *Node, user *User) (AccessDecision, error) {
	env := buildEnv(node, user)
	return c.checkPolicyExprs("node", env)
}

// CheckAccessToResource checks if a given user has access to view a resource.
func (c *PredicateAccessChecker) CheckAccessToResource(resource *Resource, user *User) (AccessDecision, error) {
	env := buildEnv(resource, user)
	return c.checkPolicyExprs("resource", env)
}

// checkPolicyExprs is the internal routine that evaluates expressions in a given scope from all policies
// with a provided execution environment containing input values.
func (c *PredicateAccessChecker) checkPolicyExprs(scope string, env map[string]any) (AccessDecision, error) {
	parser, err := newParser(env)
	if err != nil {
		return AccessUndecided, trace.Wrap(err)
	}

	evaluate := func(expr string) (bool, error) {
		ifn, err := parser.Parse(expr)
		if err != nil {
			return false, trace.Wrap(err)
		}

		b, ok := ifn.(bool)
		if !ok {
			return false, trace.BadParameter("unsupported type: %T", ifn)
		}

		return b, nil
	}

	for _, policy := range c.policies {
		if expr, ok := policy.GetDeny()[scope]; ok {
			denied, err := evaluate(expr)
			if err != nil {
				return AccessUndecided, trace.Wrap(err)
			}

			if denied {
				return AccessDenied, nil
			}
		}
	}

	for _, policy := range c.policies {
		if expr, ok := policy.GetAllow()[scope]; ok {
			allowed, err := evaluate(expr)
			if err != nil {
				return AccessUndecided, trace.Wrap(err)
			}

			if allowed {
				return AccessAllowed, nil
			}
		}
	}

	return AccessUndecided, nil
}

// Resource describes an arbitrary resource that can be viewed and listed.
type Resource struct {
	// Namespace is the namespace of the resource.
	Namespace string `json:"namespace"`

	// The resource kind.
	Kind string `json:"kind"`

	// The labels on the resource.
	Labels map[string]string `json:"labels"`

	// The verb of the operation, e.g. "list", "read" or "write".
	Verb string `json:"verb"`
}

// GetName returns the name of the object.
func (n *Resource) GetName() string {
	return "resource"
}

// Node describes a Server Access node.
type Node struct {
	// Namespace is the namespace of the node.
	Namespace string `json:"namespace"`

	// The UNIX login of the connection
	Login string `json:"login"`

	// The labels on the target node.
	Labels map[string]string `json:"labels"`
}

// GetName returns the name of the object.
func (n *Node) GetName() string {
	return "node"
}

// User describes a Teleport user.
type User struct {
	// The name of the Teleport user.
	Name string `json:"name"`

	// All access policies assigned to the user.
	Policies []string `json:"policies"`

	// All roles assigned to the user.
	Roles []string `json:"roles"`

	// SSH logins/principals assigned to the user.
	SSHLogins []string `json:"ssh_logins"`

	// The traits associated with the user.
	Traits map[string][]string `json:"traits"`
}

// GetName returns the name of the object.
func (u *User) GetName() string {
	return "user"
}
