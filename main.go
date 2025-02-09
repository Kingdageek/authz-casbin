package main

import (
	"fmt"
	"log"
	"os"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

type PolicyGroup string

const (
	User PolicyGroup = "user"
	Team PolicyGroup = "team"
	Dept PolicyGroup = "dept"
	Org PolicyGroup = "org"
	Public PolicyGroup = "public"
)

var ModelConf string = fmt.Sprintf(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, pgrp, orgId

[policy_effect]
e = some(where (p.eft == allow))

[role_definition]
g = _, _

# 7-step matching: 
# 1. for individuals: that user is object owner OR
# 2. for individuals: user has 'act' permission for 'obj' OR
# 3. for teams: user belongs to team that has 'act' permission for 'obj' OR
# 4. for depts: user belongs to dept that has 'act' for 'obj' OR
# 5. for orgs: user belongs to org that has 'act' for 'obj' OR
# 6. for org admins: user has 'admin' role for org with 'orgId'
# 7. for public sharing: sub=0, obj=id_of_shared_item, act, pgrp='public'
# To make this faster for shared files, the order of execution will be altered to move fns, and in clauses down
[matchers]
m = (p.sub == r.sub.UserId && p.act == r.act && p.obj == r.obj && p.pgrp == "%s") || \
    (p.sub == r.sub.DeptId && p.act == r.act && p.obj == r.obj && p.pgrp == "%s") || \
    (p.sub == r.sub.OrgId && p.act == r.act && p.obj == r.obj && p.pgrp == "%s") || \
    (p.sub in r.sub.Teams && p.act == r.act && p.obj == r.obj && p.pgrp == "%s") || \
    (p.sub == r.sub.UserId && g(p.act, r.act) && p.obj == r.obj && p.pgrp == "%s") || \
    ("admin" in r.sub.Roles && p.orgId == r.sub.OrgId) || \
	(p.sub == "0" && p.act == r.act && p.obj == r.obj && p.pgrp == "%s")
`, User, Dept, Org, Team, User, Public)

type RequestSub struct {
	UserId, TeamId, DeptId, OrgId string
	Roles                         []interface{}
	Teams                         []interface{}
}

func AddOwnerRole(e *casbin.Enforcer) {
	ownerPermissions := []string{"read", "write", "download", "share", "delete"}
	for _, perm := range ownerPermissions {
		hasGroupPolicy, err := e.HasNamedGroupingPolicy("g", "owner", perm)
		if err != nil {
			log.Fatalf("error checking named group policy for permission %s: %v", perm, err)
			return
		}
		if !hasGroupPolicy {
			isPolicyAdded, err := e.AddNamedGroupingPolicy("g", "owner", perm)
			if err != nil {
				log.Fatalf("couldn't add named group policy for permission %s: %v", perm, err)
				return
			}
			fmt.Printf("is %s permission added for owner: %v\n", perm, isPolicyAdded)
		}
	}
}

func main() {
	currDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	policyFile := currDir + "/config/policy.csv"
	// modelFile := currDir + "/config/model.CONF"

	m, err := model.NewModelFromString(ModelConf)
	a := fileadapter.NewAdapter(policyFile)

	if err != nil {
		log.Fatalf("error: model: %s", err)
		return
	}

	// casbin enforcer
	// e, _ := casbin.NewEnforcer(modelFile, policyFile)
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		log.Fatalf("error: enforcer: %s", err)
		return
	}

	// add the `owner` role via the casbin api
	AddOwnerRole(e)


	// test that UserId 1 has no read access to obj 3
	// var roles []interface{}
	// roles = append(roles, "slave")
	roles := []interface{}{
		[]string{"slave"},
	}
	sub := &RequestSub{
		UserId: "1", TeamId: "2", DeptId: "1", OrgId: "1",
		Roles: roles,
		Teams: []interface{}{"1"},
	}
	act := "read"
	obj := "3"
	res, err := e.Enforce(sub, obj, act)
	fmt.Println("For test that UserId 1 has no read access to obj 3: ")
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Println("Expected result: false \nresult: ", res)

	// test that owner with UserId 2 can perform all actions to obj 1
	sub = &RequestSub{
		UserId: "2", TeamId: "1", DeptId: "1", OrgId: "1",
		Roles: roles,
		Teams: []interface{}{"1"},
	}
	act = "read"
	obj = "1"
	res, err = e.Enforce(sub, obj, act)
	fmt.Println("\n\nFor test that owner with UserId 2 can perform all actions to obj 1: ")
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Println("for read: Expected result: true \nresult: ", res)

	act = "download"
	res, err = e.Enforce(sub, obj, act)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Println("for download: Expected result: true \nresult: ", res)

	act = "delete"
	res, err = e.Enforce(sub, obj, act)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Println("for delete: Expected result: true \nresult: ", res)

	// test user with id=3 that belongs to team 1 has no other access to obj=1 except read
	sub = &RequestSub{
		UserId: "3", TeamId: "1", DeptId: "1", OrgId: "1",
		Roles: roles,
		Teams: []interface{}{"1", "2"},
	}
	act = "read"
	obj = "1"
	res, err = e.Enforce(sub, obj, act)
	fmt.Println("\n\nFor test that user with id=3 that belongs to team 1 has no other access to obj=1 except read: ")
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Println("for read: Expected result: true \nresult: ", res)

	act = "share"
	res, err = e.Enforce(sub, obj, act)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Printf("for %s: Expected result: false \nresult: %v\n", act, res)

	// test that everyone in org with id=1, have ONLY read & download access to obj=2
	sub = &RequestSub{
		UserId: "3", TeamId: "1", DeptId: "1", OrgId: "1",
		Roles: roles,
		Teams: []interface{}{"1", "2"},
	}

	act = "download"
	obj = "2"
	res, err = e.Enforce(sub, obj, act)
	fmt.Println("\n\nFor test that everyone in org with id=1, have ONLY read & download access to obj=2: ")
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Printf("for %s: Expected result: true \nresult: %v\n", act, res)

	act = "delete"
	res, err = e.Enforce(sub, obj, act)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Printf("for %s: Expected result: false \nresult: %v\n", act, res)

	// test that user with "admin" role in org 1 has every access to obj 1 and 2
	sub = &RequestSub{
		UserId: "4", TeamId: "1", DeptId: "1", OrgId: "1",
		Roles: []interface{}{"admin", "team_lead"},
		Teams: []interface{}{"1", "2"},
	}

	act = "write"
	obj = "1"
	res, err = e.Enforce(sub, obj, act)
	fmt.Println("\n\nFor test that user with 'admin' role in org 1 has every access to obj 1 and 2: ")
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Printf("for %s: Expected result: true \nresult: %v\n", act, res)

	act = "delete"
	res, err = e.Enforce(sub, obj, act)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Printf("for %s: Expected result: true \nresult: %v\n", act, res)

	// test that user with "admin" role in org 2 has NO access to obj 1 and 2
	sub = &RequestSub{
		UserId: "5", TeamId: "4", DeptId: "4", OrgId: "2",
		Roles: []interface{}{"admin", "team_lead"},
		Teams: []interface{}{"1", "2"},
	}

	act = "write"
	obj = "2"
	res, err = e.Enforce(sub, obj, act)
	fmt.Println("\n\nFor test that user with 'admin' role in org 1 has every access to obj 1 and 2: ")
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Printf("for %s: Expected result: false \nresult: %v\n", act, res)

	act = "delete"
	res, err = e.Enforce(sub, obj, act)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Printf("for %s: Expected result: false \nresult: %v\n", act, res)
}
