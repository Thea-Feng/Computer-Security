package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	"errors"
	_ "errors"
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

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const anotherPassword = "anotherPassword"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentFour = "I love CS 161!"
const contentFive = "Peyrin is a nice guy."

const content100 = string('a' * 100)
const content10000000 = string('a' * 10000000)

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
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
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
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

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
	Describe("Checking proper error returns", func() {
		Specify("Inituser: creating empty user name", func() {
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("Inituser: creating duplicated user name", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("Getuser: cannot login with wrong password", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.GetUser("alice", defaultPassword+"5")
			Expect(err).ToNot(BeNil())
		})
		Specify("Getuser: cannot get a inexisted user", func() {
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("Getuser: detect malicious modification", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			datastore := userlib.DatastoreGetMap()
			for key, _ := range datastore {
				datastore[key][0] ^= 0xff
			}
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			for key, _ := range datastore {
				datastore[key][0] ^= 0xff
			}
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})
		Specify("StoreFile: Revoked user cannot modify the file again", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword+"2")
			Expect(err).To(BeNil())
			alice.StoreFile("alice_file_1", []byte(content10000000))
			invite, err := alice.CreateInvitation("alice_file_1", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, "bob_file_1")
			Expect(err).To(BeNil())
			bob.StoreFile("bob_file_1", []byte(contentTwo))
			alice.RevokeAccess("alice_file_1", "bob")
			userlib.DebugMsg("Checking that Bob cannot load message from the file.")
			_, err = bob.LoadFile("bob_file_1")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Checking that Bob cannot append message to the file.")
			err = bob.AppendToFile("bob_file_1", []byte(contentFour))
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Checking that Bob cannot store message to the file.")
			err = bob.StoreFile("bob_file_1", []byte(content100))
			Expect(err).ToNot(BeNil())
			read, err := alice.LoadFile("alice_file_1")
			Expect(err).To(BeNil())
			Expect(read).To(Equal(contentTwo))
		})
		Specify("LoadFile : Invalid Filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			_, err = alice.LoadFile("Inexisted file")
			Expect(err).ToNot(BeNil())
		})

		Specify("LoadFile : Detect malicious modification", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("alice_file_1", []byte(content10000000))
			datastore := userlib.DatastoreGetMap()
			for key, _ := range datastore {
				datastore[key][0] ^= 0xff
			}
			_, err := alice.LoadFile("alice_file_1")
			Expect(err).ToNot(BeNil())
		})
		Specify("AppendToFile : invalid filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("alice_file_1", []byte(content100))
			err = alice.AppendToFile("alice_file_2", []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})
		Specify("CreateInvitation : share inexisted file", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			_, err = alice.CreateInvitation("alice_file_1", "bob")
			Expect(err).ToNot(BeNil())
		})
		Specify("CreateInvitation : share file to inexisited user", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("alice_file_1", []byte(contentThree))
			_, err = alice.CreateInvitation("alice_file_1", "bob")
			Expect(err).ToNot(BeNil())
		})
		Specify("CreateInvitation : shared files overwriting", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			alice.StoreFile("alice_file_1", []byte(contentOne))
			bob.StoreFile("bob_file_1", []byte(contentTwo))
			invite, err := alice.CreateInvitation("alice_file_1", "bob")
			err = bob.AcceptInvitation("alice", invite, "bob_file_1")
			Expect(err).ToNot(BeNil())
		})
		Specify("AcceptInvitation : Receive file from unexpected user", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			alice.StoreFile("alice_file_1", []byte(contentThree))
			invite, err := alice.CreateInvitation("alice_file_1", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("charles", invite, "bob_file_1")
			Expect(err).ToNot(BeNil())
		})
		Specify("AcceptInvitation : User tries to steal invitation", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			alice.StoreFile("alice_file_1", []byte(contentThree))
			invite, err := alice.CreateInvitation("alice_file_1", "bob")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite, "chares_file_1")
			Expect(err).ToNot(BeNil())
		})
		Specify("AcceptInvitation : Users are not allowed to receive modified invitation", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			alice.StoreFile("alice_file_1", []byte(contentThree))
			invite, err := alice.CreateInvitation("alice_file_1", "bob")
			Expect(err).To(BeNil())
			datastore := userlib.DatastoreGetMap()
			for key, _ := range datastore {
				datastore[key][0] ^= 0xff
			}
			err = bob.AcceptInvitation("alice", invite, "bob_file_1")
			Expect(err).ToNot(BeNil())
		})
		Specify("AcceptInvitation : Revoke before accept", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("alice_file_1", []byte(contentThree))
			invite, err := alice.CreateInvitation("alice_file_1", "bob")
			Expect(err).To(BeNil())
			alice.RevokeAccess("alice_file_1", "bob")
			err = bob.AcceptInvitation("alice", invite, "bob_file_1")
			Expect(err).ToNot(BeNil())
		})
		Specify("AcceptInvitation : Cannot receive a modifed link", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("alice_file_1", []byte(contentOne))
			charles.StoreFile("alice_file_1", []byte(contentTwo))
			invite1, err := alice.CreateInvitation("alice_file_1", "bob")
			Expect(err).To(BeNil())
			invite2, err := charles.CreateInvitation("alice_file_1", "bob")
			Expect(err).To(BeNil())
			datastore := userlib.DatastoreGetMap()
			datastore[invite1] = datastore[invite2]
			err = bob.AcceptInvitation("alice", invite1, "bob_file_1")
			Expect(err).ToNot(BeNil())
		})
		Specify("Revoke: filename error", func() {
			// alice, err = client.InitUser("alice", defaultPassword)
			// Expect(err).To(BeNil())
			// bob, err = client.InitUser("bob", defaultPassword)
			// Expect(err).To(BeNil())
			// alice.StoreFile("alice_file_1",[]byte(contentThree))
			// invite,err :=alice.CreateInvitation("alice_file_1","bob")
			// Expect(err).To(BeNil())
			// err = alice.RevokeAccess("alice_file_2","bob")
			// Expect(err).NotTo(BeNil())
			// err = alice.RevokeAccess("alice_file_1","charles")
			// Expect(err).NotTo(BeNil())
			// err=bob.AcceptInvitation("alice",invite,"bob_file_1")
			// Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating share link of file %s.", aliceFile)
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking a share link with invalid filename, error expected.")
			err = alice.RevokeAccess("invalidFile", "bob")
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("Alice revoking a share link with invalid recipient, error expected.")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).NotTo(BeNil())
		})

	})
	Describe("Advanced Function Test", func() {
		Specify("StoreFile : Overwrite", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("alice_file_1", []byte(contentOne))
			result1, err := alice.LoadFile("alice_file_1")
			Expect(err).To(BeNil())
			Expect(result1).To(Equal([]byte(contentOne)))
			alice.StoreFile("alice_file_1", []byte(content100))
			result2, err := alice.LoadFile("alice_file_1")
			Expect(err).To(BeNil())
			Expect(result2).To(Equal([]byte(content100)))
		})
		Specify("Bandwidth Test", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("alice_file_1", []byte(content100))
			Expect(err).To(BeNil())
			err = alice.StoreFile("alice_file_2", []byte(content10000000))
			Expect(err).To(BeNil())
			before := userlib.DatastoreGetBandwidth()
			alice.AppendToFile("alice_file_1", []byte(contentOne))
			end := userlib.DatastoreGetBandwidth()
			bw1 := end - before
			before = userlib.DatastoreGetBandwidth()
			alice.AppendToFile("alice_file_2", []byte(contentOne))
			end = userlib.DatastoreGetBandwidth()
			bw2 := end - before

			if (bw2-bw1) < 100 || (bw1-bw2) < 100 {
				err = nil
			} else {
				err = errors.New("bandwidth varies too much")
			}
			Expect(err).To(BeNil())

		})
		Specify("Multisession: File Sync", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			charles, err = client.InitUser("charles", defaultPassword)
			alicePhone.StoreFile("alice_file_1", []byte(contentOne))
			invite, err := aliceLaptop.CreateInvitation("alice_file_1", "bob")
			Expect(err).To(BeNil())
			bob.AcceptInvitation("alice", invite, "bob_file_1")
			bob.AppendToFile("bob_file_1", []byte(contentTwo))
			aliceLaptop.AppendToFile("alice_file_1", []byte(contentThree))
			invite, err = aliceLaptop.CreateInvitation("alice_file_1", "charles")
			charles.AcceptInvitation("alice", invite, "charles_file_1")
			charles.AppendToFile("charles_file_1", []byte(contentFour))
			read, err := aliceDesktop.LoadFile("alice_file_1")
			Expect(read).To(Equal([]byte(contentOne + contentTwo + contentThree + contentFour)))
		})
		Specify("File Sharing to many users and revoke from the middle", func() {
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
			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())
			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())
			horace, err = client.InitUser("horace", defaultPassword)
			Expect(err).To(BeNil())
			ira, err = client.InitUser("ira", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("alice_file_1", []byte(contentFive))
			invite, err := alice.CreateInvitation("alice_file_1", "bob")
			Expect(err).To(BeNil())
			bob.AcceptInvitation("alice", invite, "bob_file_1")
			invite, err = alice.CreateInvitation("alice_file_1", "charles")
			Expect(err).To(BeNil())
			charles.AcceptInvitation("alice", invite, "charles_file_1")
			invite, err = bob.CreateInvitation("bob_file_1", "doris")
			Expect(err).To(BeNil())
			doris.AcceptInvitation("bob", invite, "doris_file_1")
			invite, err = bob.CreateInvitation("bob_file_1", "eve")
			Expect(err).To(BeNil())
			eve.AcceptInvitation("bob", invite, "eve_file_1")
			invite, err = charles.CreateInvitation("charles_file_1", "frank")
			Expect(err).To(BeNil())
			frank.AcceptInvitation("charles", invite, "frank_file_1")
			invite, err = charles.CreateInvitation("charles_file_1", "grace")
			Expect(err).To(BeNil())
			grace.AcceptInvitation("charles", invite, "grace_file_1")
			invite, err = doris.CreateInvitation("doris_file_1", "horace")
			Expect(err).To(BeNil())
			horace.AcceptInvitation("doris", invite, "horace_file_1")
			invite, err = horace.CreateInvitation("horace_file_1", "ira")
			Expect(err).To(BeNil())
			ira.AcceptInvitation("horace", invite, "ira_file_1")
			bob.RevokeAccess("bob_file_1", "doris")
			_, err = bob.LoadFile("bob_file_1")
			Expect(err).To(BeNil())
			_, err = charles.LoadFile("charles_file_1")
			Expect(err).To(BeNil())
			_, err = doris.LoadFile("doris_file_1")
			Expect(err).ToNot(BeNil())
			_, err = eve.LoadFile("eve_file_1")
			Expect(err).To(BeNil())
			_, err = frank.LoadFile("frank_file_1")
			Expect(err).To(BeNil())
			_, err = grace.LoadFile("grace_file_1")
			Expect(err).To(BeNil())
			_, err = horace.LoadFile("horace_file_1")
			Expect(err).ToNot(BeNil())
			_, err = ira.LoadFile("ira_file_1")
			Expect(err).ToNot(BeNil())
			grace.StoreFile("grace_file_1", []byte(contentOne))
			read, err := alice.LoadFile("alice_file_1")
			Expect(err).To(BeNil())
			Expect(read).To(Equal([]byte(contentOne)))
			alice.RevokeAccess("alice_file_1", "charles")
			_, err = charles.LoadFile("charles_file_1")
			Expect(err).ToNot(BeNil())
			_, err = frank.LoadFile("frank_file_1")
			Expect(err).ToNot(BeNil())
			_, err = grace.LoadFile("grace_file_1")
			Expect(err).ToNot(BeNil())
			err = frank.StoreFile("frank_file_1", []byte(contentThree))
			Expect(err).ToNot(BeNil())

		})
	})
	Describe("Edge cases", func() {
		Specify("Init Users: empty password", func() {
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())
		})
		Specify("Store File: empty file content", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("alice_file_1", []byte(""))
			Expect(err).To(BeNil())
		})
		Specify("Store File: empty filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("", []byte(content100))
			Expect(err).To(BeNil())
		})
		Specify("Appending: empty file content", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())
			err = alice.StoreFile("alice_file_1", []byte(""))
			Expect(err).To(BeNil())
			err = alice.AppendToFile("alice_file_1", []byte(""))
			Expect(err).To(BeNil())
		})
	})
})
