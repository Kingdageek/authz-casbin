package main

import (
	"fmt"
	"os"

	"github.com/casbin/casbin/v2"
)

type RequestSub struct {
	UserId, TeamId, DeptId, OrgId string
	Roles                         []interface{}
	Teams                         []interface{}
}

func main() {
	currDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	policyFile := currDir + "/config/policy.csv"
	modelFile := currDir + "/config/model.CONF"

	// casbin enforcer
	e, _ := casbin.NewEnforcer(modelFile, policyFile)

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
