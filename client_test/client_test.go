package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	"fmt"
	"github.com/google/uuid"
	_ "strconv"
	_ "strings"
	"testing"
	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

func content_match(b string, a string) (ok bool) {
	ok = true
	for i, v := range a {
		if string(v) == string(b[0]) {
			for j := 0; j < len(b); j++ {
				if j+i >= len(a) {
					return false
				}
				if b[j] == a[j+i] {
					continue
				} else {
					ok = false
					break
				}
			}
			if !ok {
				ok = true
				continue
			} else {
				return ok
				break
			}
		}
	}
	return false
}

func measureBandwidth(probe func()) (bandwidth int) {
	before := userlib.DatastoreGetBandwidth()
	probe()
	after := userlib.DatastoreGetBandwidth()
	return after - before
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User

	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Additional Tests", func() {
		Specify("Additional Test: empty username/password/filename.", func() {
			userlib.DebugMsg("Initializing user ''.")
			alice, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user 'alice'.")
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Storing file data: %s", contentOne)
			err = alice.StoreFile(emptyString, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("Additional Test: repeated username/password check(simple password check).", func() {
			userlib.DebugMsg("Initializing user alice.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var ori_res map[uuid.UUID][]byte
			ori_res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_res[i] = v
			}

			userlib.DebugMsg("Initializing user alice.")
			alicePhone, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			alicePhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("if same password turns out the same in datastore.")
			var res map[uuid.UUID][]byte
			res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				_, flag := ori_res[i]
				if !flag {
					res[i] = v
				}
			}

			for _, v := range res {
				for _, v2 := range ori_res {
					if string(v2) == string(v) {
						err = fmt.Errorf("unsafe password saving")
					}
				}
			}
			Expect(err).To(BeNil())
		})

		Specify("Additional Test: username case sensitive.", func() {
			userlib.DebugMsg("Initializing user 'alice'.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'alice'.")
			alicePhone, err = client.InitUser("ALICE", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Additional Test: multipal instance load/append/store.", func() {
			userlib.DebugMsg("Initializing user 'alice'.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'alice'.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees expected file data.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentTwo)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees expected file data.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("alicePhone storing file %s with content: %s", aliceFile, contentOne)
			err = alicePhone.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("alicePhone appending to file %s, content: %s", aliceFile, contentTwo)
			err = alicePhone.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Additional Test: Constant number of public key.", func() {
			userlib.DebugMsg("Initializing user 'alice'.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'bob'.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			n1 := len(userlib.KeystoreGetMap())

			userlib.DebugMsg("Alice Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Bob Storing file data: %s", contentOne)
			//err = bob.StoreFile(bobFile, []byte(contentOne))
			//Expect(err).To(BeNil())

			n2 := len(userlib.KeystoreGetMap())
			Expect(n1).To(Equal(n2))

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			n3 := len(userlib.KeystoreGetMap())
			Expect(n1).To(Equal(n3))
			Expect(n2).To(Equal(n3))
		})

		Specify("Additional Test: filename unique in one namespace.", func() {
			userlib.DebugMsg("Initializing user 'alice'.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'bob'.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob Storing file data: %s", contentOne)
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

		})

		Specify("Additional Test: Load/append/create_invitaion to not existed file.", func() {
			userlib.DebugMsg("Initializing user 'alice'.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'bob'.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			bob.StoreFile(bobFile, []byte(contentTwo))

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Loading file...")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

		})

		Specify("Additional Test: Check if all shared user can operate the share file"+
			"and load the newest file .", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("charles appending file data: %s", contentTwo)
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the new file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("charles store file data: %s", contentThree)
			err = charles.StoreFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the new file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Bob appending file data: %s", contentThree)
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the new file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree + contentThree)))
		})

		Specify("Additional Test: Create invitaion for not exsited user and file.", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Initializing file_sharing tree.")
			userlib.DebugMsg("Alice creating invite for Bob for file %s, and accepting invite under name %s.",
				aliceFile, bobFile)

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			_, err = alice.CreateInvitation(bobFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Additional Test: Create invitaion for who has already been authorized.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charlie, Doris, Eve.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Initializing file_sharing tree.")
			userlib.DebugMsg("Alice creating invite for Bob and Charles for file %s, and they accepting invite under names %s.",
				aliceFile, bobFile+", "+charlesFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Doris and Eve for file %s, and they accepting invite under names %s.",
				bobFile, dorisFile+", "+eveFile)

			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			invite, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("bob", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s", bobFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob creating invite for Eve for file %s", bobFile)
			invite, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles creating invite for Doris for file %s", charlesFile)
			invite, err = charles.CreateInvitation(charlesFile, "doris")
			Expect(err).ToNot(BeNil())
		})

		Specify("Additional Test: Create invitaion that would make a ill-formed tree.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charlie, Doris, Eve.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Initializing file_sharing tree.")
			userlib.DebugMsg("Alice creating invite for Bob and Charles for file %s, and they accepting invite under names %s.",
				aliceFile, bobFile+", "+charlesFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Doris and Eve for file %s, and they accepting invite under names %s.",
				bobFile, dorisFile+", "+eveFile)

			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			invite, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("bob", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for alice for file %s", bobFile)
			invite, err = bob.CreateInvitation(bobFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Doris creating invite for alice for file %s", dorisFile)
			invite, err = charles.CreateInvitation(dorisFile, "alice")
			Expect(err).ToNot(BeNil())
		})

		Specify("Additional Test: Efficiently append.", func() {
			contentLarge := userlib.RandomBytes(1048576) //1GB
			aliceFile1 := "aliceFile1.txt"
			aliceFile2 := "aliceFile2.txt"

			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing small file %s with content: %s", aliceFile1, contentOne)
			err = alice.StoreFile(aliceFile1, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing large file %s with Large content", aliceFile2)
			err = alice.StoreFile(aliceFile2, contentLarge)
			Expect(err).To(BeNil())

			t1 := measureBandwidth(func() {
				userlib.DebugMsg("Alice appending to small file %s with content: %s", aliceFile1, contentTwo)
				err = alice.AppendToFile(aliceFile1, []byte(contentTwo))
				Expect(err).To(BeNil())

			})

			t2 := measureBandwidth(func() {
				userlib.DebugMsg("Alice appending to Large file %s with content: %s", aliceFile2, contentTwo)
				err = alice.AppendToFile(aliceFile2, []byte(contentTwo))
				Expect(err).To(BeNil())
			})

			if t1 != t2 {
				err = fmt.Errorf("not efficient enough")
			}
			Expect(err).To(BeNil())
		})

		Specify("Additional Test: integrity and confidentiality of user struct.", func() {
			var ori_res map[uuid.UUID][]byte
			ori_res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_res[i] = v
			}

			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var res map[uuid.UUID][]byte
			res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				res[i] = v
			}

			for i, v := range res {
				_, flag := ori_res[i]
				if flag {
					continue
				} else {
					ok := content_match("alice", string(v))
					if ok {
						//fmt.Println(string(v))
						err = fmt.Errorf("no confidentiality")
					}
					ok = content_match(string(userlib.Hash([]byte("alice"))), string(v))
					if ok {
						//fmt.Println(string(v))
						err = fmt.Errorf("no confidentiality")
					}
					ok = content_match(defaultPassword, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(string(userlib.Hash([]byte(defaultPassword))), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					Expect(err).To(BeNil())
					res[i] = userlib.RandomBytes(len(v))
					userlib.DatastoreSet(i, res[i])

					userlib.DebugMsg("Getting user 'alicePhone'.")
					alicePhone, err = client.GetUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())

					userlib.DebugMsg("Checking that if Alice can find the changes by inituser.")
					aliceDesktop, err = client.InitUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())

					userlib.DatastoreSet(i, v)
					err = nil
				}
			}

			for i, v := range res {
				_, flag := ori_res[i]
				if flag {
					continue
				} else {
					res[i] = userlib.RandomBytes(len(v))
					userlib.DatastoreSet(i, res[i])
				}
			}

			userlib.DebugMsg("Checking that if Alice can find the changes by login.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that if Alice can find the changes by inituser.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Additional Test: integrity and confidentiality of file content.", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var ori_res map[uuid.UUID][]byte
			ori_res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_res[i] = v
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			var res map[uuid.UUID][]byte
			res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				res[i] = v
			}

			for i, v := range res {
				_, flag := ori_res[i]
				if flag {
					continue
				} else {
					err = nil
					ok := content_match(contentOne, string(v))
					if ok {
						//fmt.Println(string(v))
						err = fmt.Errorf("no confidentiality")
					}
					ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
					if ok {
						//fmt.Println(string(v))
						err = fmt.Errorf("no confidentiality")
					}
					ok = content_match(aliceFile, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					Expect(err).To(BeNil())
					res[i] = userlib.RandomBytes(len(v))
					userlib.DatastoreSet(i, res[i])

					userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
					_, err = alice.LoadFile(aliceFile)
					Expect(err).ToNot(BeNil())

					userlib.DatastoreSet(i, v)
				}
			}

			for i, v := range res {
				_, flag := ori_res[i]
				if flag {
					continue
				} else {
					res[i] = userlib.RandomBytes(len(v))
					userlib.DatastoreSet(i, res[i])
				}
			}

			userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that if Alice can find the changes by appending.")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that if Alice can find the changes by storing.")
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			for i, v := range ori_res {
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}

			userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that if Alice can find the changes by appending.")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that if Alice can find the changes by storing.")
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())
		})

		Specify("Additional Test: integrity and confidentiality of sharing invitations.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			var ori_ori_res map[uuid.UUID][]byte
			ori_ori_res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_ori_res[i] = v
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			var ori_res map[uuid.UUID][]byte
			ori_res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_res[i] = v
			}

			var fileReleventuuid []uuid.UUID
			var fileReleventcontent []string
			for i, v := range ori_res {
				_, flag := ori_ori_res[i]
				if flag {
					continue
				} else {
					fileReleventuuid = append(fileReleventuuid, i)
					fileReleventcontent = append(fileReleventcontent, string(v))
				}
			}

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			var res map[uuid.UUID][]byte
			res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				res[i] = v
			}
			//fmt.Println("*************************************************")
			//fmt.Println(len(res) - len(ori_res))
			//fmt.Println("*************************************************")
			userlib.DebugMsg("Checking confidentiality")
			for i, v := range res {
				_, flag := ori_res[i]
				if flag {
					continue
				} else {
					ok := content_match("bob", string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(contentOne, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(aliceFile, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					for _, v2 := range fileReleventuuid {
						ok = content_match(v2.String(), string(v))
						if ok {
							err = fmt.Errorf("no confidentiality")
							break
						}
					}
					for _, v2 := range fileReleventcontent {
						ok = content_match(v2, string(v))
						if ok {
							err = fmt.Errorf("no confidentiality")
							break
						}
					}
					Expect(err).To(BeNil())
				}
			}

			for i, v := range res {
				_, flag := ori_res[i]
				if flag {
					continue
				} else {
					res[i] = userlib.RandomBytes(len(v))
					userlib.DatastoreSet(i, res[i])
				}
			}

			for i, _ := range res {
				if i.String() == invite.String() {
					err = fmt.Errorf("no confidentiality")
				}
				Expect(err).To(BeNil())
			}

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Additional Test: Testing Revoke in detail", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Error revoke input.")
			err = bob.RevokeAccess(bobFile, "alice")
			Expect(err).ToNot(BeNil())
			err = bob.RevokeAccess(aliceFile, "alice")
			Expect(err).ToNot(BeNil())
			err = charles.RevokeAccess(charlesFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentTwo)
			alice.StoreFile(aliceFile, []byte(contentTwo))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice append file %s with content: %s", aliceFile, contentThree)
			alice.AppendToFile(aliceFile, []byte(contentThree))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot store the file.")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

		})

		Specify("Additional Test: Length leaking test / raw hash test", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			var res map[uuid.UUID][]byte
			res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				res[i] = v
			}

			for _, v := range res {
				ok := content_match(contentOne, string(v))
				if ok {
					err = fmt.Errorf("not safe")
				}
				ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
				if ok {
					err = fmt.Errorf("not safe")
				}
				ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
				if ok {
					err = fmt.Errorf("not safe")
				}
				ok = content_match(invite.String(), string(v))
				if ok {
					err = fmt.Errorf("not safe")
				}
				ok = content_match(string(userlib.Hash([]byte(invite.String()))), string(v))
				if ok {
					err = fmt.Errorf("not safe")
				}
			}
			Expect(err).To(BeNil())
		})

		Specify("Additional Test: Single copy check", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			var res1 map[uuid.UUID][]byte
			res1 = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				res1[i] = v
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			var res2 map[uuid.UUID][]byte
			res2 = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				_, flag := res1[i]
				if !flag {
					res2[i] = v
				}
			}

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking no new copy")

			//var res3 map[uuid.UUID][]byte
			//res3 = make(map[uuid.UUID][]byte)
			//num := 0
			for i1, v1 := range res2 {
				for i, v := range userlib.DatastoreGetMap() {
					if i1 == i {
						continue
					}
					if string(v1) == string(v) {
						err = fmt.Errorf("copy pattern error")
					}
				}
			}
			Expect(err).To(BeNil())

		})

		Specify("Additional Test: Testing Create/Accept Invite Functionality.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for not exsited user.")
			_, err = alice.CreateInvitation(aliceFile, "charlie")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob storing file %s with content: %s", bobFile, contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting repeated filename test")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepting no exsited username test")
			err = bob.AcceptInvitation("charles", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Additional Test: append test.", func() {
			userlib.DebugMsg("Initializing user 'alice'.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			var ori_db map[uuid.UUID][]byte
			ori_db = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_db[i] = v
			}

			userlib.DebugMsg("alice appending to file %s, content: %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			var db map[uuid.UUID][]byte
			db = make(map[uuid.UUID][]byte)
			//for i, v := range userlib.DatastoreGetMap() {
			//	db[i] = v
			//}

			for i, v := range userlib.DatastoreGetMap() {
				v2, flag := ori_db[i]
				if flag {
					if string(v2) != string(v) {
						db[i] = v
					}
				} else {
					db[i] = v
				}
			}

			for i, v := range db {
				userlib.DatastoreSet(i, userlib.RandomBytes(len(v)))

				userlib.DebugMsg("alice appending to file %s, content: %s", aliceFile, contentTwo)
				err = alice.AppendToFile(aliceFile, []byte(contentTwo))
				Expect(err).ToNot(BeNil())

				userlib.DatastoreSet(i, v)
			}

		})

		Specify("Additional Test: Create invitaion test", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			var ori_db map[uuid.UUID][]byte
			ori_db = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_db[i] = v
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			var db map[uuid.UUID][]byte
			db = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				_, flag := ori_db[i]
				if !flag {
					db[i] = v
				}
			}

			userlib.DebugMsg("Initializing file_sharing tree.")
			userlib.DebugMsg("Alice creating invite for Bob for file %s, and accepting invite under name %s.",
				aliceFile, bobFile)

			for i, v := range db {
				userlib.DatastoreSet(i, userlib.RandomBytes(len(v)))

				_, err := alice.CreateInvitation(aliceFile, "bob")
				Expect(err).ToNot(BeNil())

				userlib.DatastoreSet(i, v)
			}
		})

		Specify("Additional Test: Testing Create/Accept Invite after revoking.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile+"1")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile+"2")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Additional Test: Accept invitaion test", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			var ori_db map[uuid.UUID][]byte
			ori_db = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_db[i] = v
			}

			userlib.DebugMsg("Initializing file_sharing tree.")
			userlib.DebugMsg("Alice creating invite for Bob for file %s, and accepting invite under name %s.",
				aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			var db map[uuid.UUID][]byte
			db = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				_, flag := ori_db[i]
				if !flag {
					db[i] = v
				}
			}

			for i, v := range db {
				userlib.DatastoreSet(i, userlib.RandomBytes(len(v)))

				err := alice.AcceptInvitation("alice", invite, bobFile)
				Expect(err).ToNot(BeNil())

				userlib.DatastoreSet(i, v)
			}
		})

		Specify("Additional Test: revoke additional test.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			var ori_db map[uuid.UUID][]byte
			ori_db = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_db[i] = v
			}

			userlib.DebugMsg("alice creating invite for Bob.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			var db map[uuid.UUID][]byte
			db = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				_, flag := ori_db[i]
				if !flag {
					db[i] = v
				}
			}

			userlib.DebugMsg("Alice revoking not exsited file.")
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking not owned user.")
			err = alice.RevokeAccess(aliceFile, "eve")
			Expect(err).ToNot(BeNil())

			for i, v := range db {
				userlib.DatastoreSet(i, userlib.RandomBytes(len(v)))

				fmt.Println(len(db))

				userlib.DebugMsg("Alice malicious revoking test.")
				err = alice.RevokeAccess(aliceFile, "bob")
				Expect(err).ToNot(BeNil())

				//if err != nil {
				//	break
				//}

				userlib.DatastoreSet(i, v)
			}

		})

		Specify("Additional Test: additional test for file content.", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var ori_res map[uuid.UUID][]byte
			ori_res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_res[i] = v
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			var res map[uuid.UUID][]byte
			res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				res[i] = v
			}

			for i, v := range res {
				_, flag := ori_res[i]
				if flag {
					continue
				} else {
					err = nil
					ok := content_match(contentOne, string(v))
					if ok {
						//fmt.Println(string(v))
						err = fmt.Errorf("no confidentiality")
					}
					ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
					if ok {
						//fmt.Println(string(v))
						err = fmt.Errorf("no confidentiality")
					}
					ok = content_match(aliceFile, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					Expect(err).To(BeNil())
					res[i] = userlib.RandomBytes(len(v))
					userlib.DatastoreSet(i, res[i])

					userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
					_, err = alice.LoadFile(aliceFile)
					Expect(err).ToNot(BeNil())

					userlib.DatastoreSet(i, v)
				}
			}

			for i, v := range ori_res {
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}

			userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that if Alice can find the changes by appending.")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that if Alice can find the changes by storing.")
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())
		})

		Specify("Additional Test: integrity and confidentiality of sharing invitations.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			var ori_ori_res map[uuid.UUID][]byte
			ori_ori_res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_ori_res[i] = v
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			var ori_res map[uuid.UUID][]byte
			ori_res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_res[i] = v
			}

			var fileReleventuuid []uuid.UUID
			var fileReleventcontent []string
			for i, v := range ori_res {
				_, flag := ori_ori_res[i]
				if flag {
					continue
				} else {
					fileReleventuuid = append(fileReleventuuid, i)
					fileReleventcontent = append(fileReleventcontent, string(v))
				}
			}

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			var res map[uuid.UUID][]byte
			res = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				res[i] = v
			}
			//fmt.Println("*************************************************")
			//fmt.Println(len(res) - len(ori_res))
			//fmt.Println("*************************************************")
			userlib.DebugMsg("Checking confidentiality")
			for i, v := range res {
				_, flag := ori_res[i]
				if flag {
					continue
				} else {
					ok := content_match("bob", string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(contentOne, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(aliceFile, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
					for _, v2 := range fileReleventuuid {
						ok = content_match(v2.String(), string(v))
						if ok {
							err = fmt.Errorf("no confidentiality")
							break
						}
					}
					for _, v2 := range fileReleventcontent {
						ok = content_match(v2, string(v))
						if ok {
							err = fmt.Errorf("no confidentiality")
							break
						}
					}
					Expect(err).To(BeNil())
				}
			}

			//for i, v := range res {
			//	_, flag := ori_res[i]
			//	if flag {
			//		continue
			//	} else {
			//		res[i] = userlib.RandomBytes(len(v))
			//		userlib.DatastoreSet(i, res[i])
			//
			//		err = bob.AcceptInvitation("alice", invite, bobFile)
			//		Expect(err).ToNot(BeNil())
			//
			//		userlib.DatastoreSet(i, v)
			//	}
			//}

			for i, v := range ori_ori_res {
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}

			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Additional Test: Accept invitaion test2 -- signature not match", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Charles storing file %s with content: %s", charlesFile, contentOne)
			charles.StoreFile(charlesFile, []byte(contentOne))

			var ori_db map[uuid.UUID][]byte
			ori_db = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				ori_db[i] = v
			}

			userlib.DebugMsg("Initializing file_sharing tree.")
			userlib.DebugMsg("Alice creating invite for Bob for file %s, and accepting invite under name %s.",
				aliceFile, bobFile)

			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			invite2, err := charles.CreateInvitation(charlesFile, "alice")
			Expect(err).To(BeNil())

			var db map[uuid.UUID][]byte
			db = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				_, flag := ori_db[i]
				if !flag {
					db[i] = v
				}
			}

			userlib.DebugMsg("bob cant verify that the secure file share invitation pointed to by the given invitationPtr was created by senderUsername.")
			userlib.DebugMsg("Wrong invitaion(not for you).")
			err = bob.AcceptInvitation("charles", invite2, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Wrong signature(for you but wrong senderusername).")
			err = bob.AcceptInvitation("charles", invite1, bobFile)
			Expect(err).ToNot(BeNil())

			//userlib.DebugMsg("integrity.")
			//i_alter := uuid.MustParse(invite1.String()[:len(invite1.String())-2] + "qq")
			//err = bob.AcceptInvitation("alice", i_alter, bobFile)
			//Expect(err).ToNot(BeNil())
		})
	})

})
