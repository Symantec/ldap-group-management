package main

import (
	"testing"
)

const (
	userWithPerm    = "user3"
	userWithoutPerm = "user2"
)

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
