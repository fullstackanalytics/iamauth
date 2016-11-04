package iamauth

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// collection of drivers that maps driver name to its factory method, with config input
var drivers = make(map[string]func(string) (Driver, error))

// underlying service to retrieve IAM users
type Driver interface {

	// query users
	GetIamUsers() ([]*UserRecord, error)

	// show a project id of some sort.
	Project() string
}

type UserRecord struct {
	Email, Role string
	LastUpdated time.Time
}

// A client API for interacting with IAM users.
type UserStore struct {
	Driver
	sync.RWMutex

	// hashmap with where key is user and value is the user's role
	m map[string]string

	LastUpdate time.Time
}

// register the driver with 1 or more names
func Register(fn func(pro string) (Driver, error), names ...string) {
	if fn == nil {
		log.Panic("nil factory method")
	}

	for _, nm := range names {
		drivers[nm] = fn
	}
}

// Create a new UserStore from the name of the driver
func New(name, proj string) (*UserStore, error) {
	fn, ok := drivers[name]
	if !ok {
		return nil, fmt.Errorf("users; %s is not a valid iam users driver", name)
	}

	d, err := fn(proj)
	if err != nil {
		return nil, err
	}

	s := &UserStore{
		Driver: d,
		m:      make(map[string]string),
	}

	return s, nil
}

// fetches latest IAM users and returns number of updates records
func (store *UserStore) Reindex() (n int, err error) {
	records, err := store.GetIamUsers()
	log.Println("records", records)
	if err != nil {
		return
	}

	defer store.Unlock()
	store.Lock()

	for _, r := range records {

		role, ok := store.m[r.Email]
		if !ok || (role != r.Role) {
			store.m[r.Email] = r.Role
			n++
		}
	}

	return
}

// find a user by email with optional acceptable roles
func (store *UserStore) Search(email string, roles ...string) (r *UserRecord, ok bool) {
	r = new(UserRecord)

	defer store.RUnlock()
	store.RLock()

	role, ok := store.m[email]
	if !ok {
		return
	}
	r.Email = email
	r.Role = role
	r.LastUpdated = store.LastUpdate

	return
}
