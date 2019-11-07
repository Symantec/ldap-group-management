package main

import (
	"testing"
)

const (
	userWithPerm    = "user3"
	userWithoutPerm = "user2"
	input           = "group3"
)

var resourcesAllow = []string{"*", "group3*"}
var resourcesDeny = []string{"group2", "group33", "group33*"}

type resourcePerm struct {
	resourceType int
	resource     string
	permission   int
}

var resourcePermList = []resourcePerm{
	resourcePerm{resourceGroup, "group1", permDelete},
	resourcePerm{resourceGroup, "group1", permCreate},
	resourcePerm{resourceSVC, "new_svc_account", permCreate},
	resourcePerm{resourceGroup, "foo", permCreate},
}

func TestCanPerformAction(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		t.Fatal(err)
	}

	for _, item := range resourcePermList {
		allow, err := state.canPerformAction(userWithPerm, item.resource, item.resourceType, item.permission)
		if err != nil {
			t.Fatal(err)
		}
		if allow != true {
			t.Errorf("got %v want %v", allow, true)
		}

		allow, err = state.canPerformAction(userWithoutPerm, item.resource, item.resourceType, item.permission)
		if err != nil {
			t.Fatal(err)
		}
		if allow != false {
			t.Errorf("got %v want %v", allow, false)
		}
	}

}

func TestCheckResourceMatch(t *testing.T) {
	for _, resource := range resourcesAllow {
		match, err := checkResourceMatch(resource, input)
		if err != nil {
			t.Fatal(err)
		}
		if match != true {
			t.Errorf("%v got %v want true", resource, match)
		}
	}

	for _, resource := range resourcesDeny {
		match, err := checkResourceMatch(resource, input)
		if err != nil {
			t.Fatal(err)
		}
		if match != false {
			t.Errorf("%v got %v want true", resource, match)
		}
	}
}
