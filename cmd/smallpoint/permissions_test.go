package main

import (
	"log"
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

func mockPermissionDB(state RuntimeState) error {
	_, err := state.db.Exec(`delete from permissions`)
	if err != nil {
		return err
	}
	var insertStmt = `insert  into permissions(groupname, resource_type, resource, permission) values (?,?,?,?);`
	stmt, err := state.db.Prepare(insertStmt)
	if err != nil {
		log.Print("Error preparing statement" + insertStmt)
		log.Fatal(err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec("group2", resourceGroup, "group1", permDelete|permCreate)
	if err != nil {
		return err
	}
	_, err = stmt.Exec("group2", resourceSVC, "new_svc_account", permCreate)
	if err != nil {
		return err
	}
	_, err = stmt.Exec("group2", resourceGroup, "foo", permCreate)
	if err != nil {
		return err
	}
	return nil
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

	err = mockPermissionDB(state)
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
