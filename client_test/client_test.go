package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	"strings"
	_ "strings"
	"testing"

	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"fmt"

	"github.com/cs161-staff/project2-starter-code/client"
	userlib "github.com/cs161-staff/project2-userlib"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
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
	// var doris *client.User
	// var eve *client.User
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

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

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

	// User-auth
	Describe("User Authentication Testing", func() {
		Specify("Case-sensitive usernames", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceUpper, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			// Both should be different users
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = aliceUpper.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = aliceUpper.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Special characters in username", func() {
			_, err = client.InitUser("alice@email.com", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.InitUser("user-name_123", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.InitUser("user with spaces", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Empty password is valid", func() {
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", "")
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Long username and password", func() {
			longUsername := strings.Repeat("a", 1000)
			longPassword := strings.Repeat("p", 1000)

			alice, err = client.InitUser(longUsername, longPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser(longUsername, longPassword)
			Expect(err).To(BeNil())
		})

		Specify("Password change should fail (implicit test)", func() {
			alice, err = client.InitUser("alice", "password1")
			Expect(err).To(BeNil())

			// Try to "change" password by creating user again
			_, err = client.InitUser("alice", "password2")
			Expect(err).ToNot(BeNil())

			// Original password should still work
			aliceLaptop, err = client.GetUser("alice", "password1")
			Expect(err).To(BeNil())

			// New password should not work
			_, err = client.GetUser("alice", "password2")
			Expect(err).ToNot(BeNil())
		})

		Specify("Multiple concurrent sessions for same user", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// All sessions should be independent but see same data
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})
	})

	Describe("File Operations Testing", func() {
		Specify("Empty filename is valid", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Special characters in filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			specialNames := []string{
				"file with spaces.txt",
				"file@#$%.txt",
				"file/with/slashes.txt",
				"file\\with\\backslashes.txt",
				"file\nwith\nnewlines.txt",
				"file\twith\ttabs.txt",
			}

			for _, name := range specialNames {
				err = alice.StoreFile(name, []byte(contentOne))
				Expect(err).To(BeNil())

				data, err := alice.LoadFile(name)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))
			}
		})

		Specify("Very long filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			longFilename := strings.Repeat("a", 10000)

			err = alice.StoreFile(longFilename, []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(longFilename)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Binary file content", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			binaryContent := make([]byte, 1000)
			for i := range binaryContent {
				binaryContent[i] = byte(i % 256)
			}

			err = alice.StoreFile(aliceFile, binaryContent)
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal(binaryContent))
		})

		Specify("File with null bytes", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			contentWithNulls := []byte("content\x00with\x00null\x00bytes")

			err = alice.StoreFile(aliceFile, contentWithNulls)
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal(contentWithNulls))
		})

		Specify("StoreFile completely overwrites including previous appends", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			// Overwrite entire file
			err = alice.StoreFile(aliceFile, []byte("new content"))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("new content")))
		})

		Specify("Multiple users, multiple files each", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// Alice creates multiple files
			for i := 0; i < 10; i++ {
				filename := fmt.Sprintf("alice_file_%d.txt", i)
				err = alice.StoreFile(filename, []byte(fmt.Sprintf("alice content %d", i)))
				Expect(err).To(BeNil())
			}

			// Bob creates multiple files
			for i := 0; i < 10; i++ {
				filename := fmt.Sprintf("bob_file_%d.txt", i)
				err = bob.StoreFile(filename, []byte(fmt.Sprintf("bob content %d", i)))
				Expect(err).To(BeNil())
			}

			// Verify all files
			for i := 0; i < 10; i++ {
				filename := fmt.Sprintf("alice_file_%d.txt", i)
				data, err := alice.LoadFile(filename)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(fmt.Sprintf("alice content %d", i))))
			}

			for i := 0; i < 10; i++ {
				filename := fmt.Sprintf("bob_file_%d.txt", i)
				data, err := bob.LoadFile(filename)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(fmt.Sprintf("bob content %d", i))))
			}
		})
	})

	Describe("Sharing/Revocation Testing", func() {
		Specify("Append efficiency: Multiple appends should use constant bandwidth", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// Measure bandwidth for first append
			bw1 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("X"))
			Expect(err).To(BeNil())
			bw1 = userlib.DatastoreGetBandwidth() - bw1

			// Append many more times
			for i := 0; i < 100; i++ {
				err = alice.AppendToFile(aliceFile, []byte("X"))
				Expect(err).To(BeNil())
			}

			// Measure bandwidth for 102nd append
			bw2 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("X"))
			Expect(err).To(BeNil())
			bw2 = userlib.DatastoreGetBandwidth() - bw2

			// Bandwidth should be approximately the same
			Expect(bw2).To(BeNumerically("~", bw1, float64(bw1)*0.1))
		})

		Specify("Append efficiency: Should not scale with file size", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// Create small file and append
			err = alice.StoreFile(aliceFile, []byte("small"))
			Expect(err).To(BeNil())

			bw1 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("X"))
			Expect(err).To(BeNil())
			bw1 = userlib.DatastoreGetBandwidth() - bw1

			// Create large file (1MB) and append
			largeContent := make([]byte, 1000000)
			err = alice.StoreFile(bobFile, largeContent)
			Expect(err).To(BeNil())

			bw2 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(bobFile, []byte("X"))
			Expect(err).To(BeNil())
			bw2 = userlib.DatastoreGetBandwidth() - bw2

			// Bandwidth should be similar regardless of file size
			Expect(bw2).To(BeNumerically("~", bw1, float64(bw1)*0.1))
		})

		Specify("Append efficiency: Empty append should use minimal bandwidth", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bw := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())
			bw = userlib.DatastoreGetBandwidth() - bw

			// Should use minimal bandwidth (just overhead, no actual content)
			Expect(bw).To(BeNumerically("<", 5000))
		})

		Specify("Append efficiency: Should not scale with previous append size", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("initial"))
			Expect(err).To(BeNil())

			// Append huge amount of data
			hugeContent := make([]byte, 1000000)
			err = alice.AppendToFile(aliceFile, hugeContent)
			Expect(err).To(BeNil())

			// Next small append should not download the huge content
			bw := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("small"))
			Expect(err).To(BeNil())
			bw = userlib.DatastoreGetBandwidth() - bw

			// Should be small, not proportional to 1MB
			Expect(bw).To(BeNumerically("<", 10000))
		})

		Specify("Append efficiency: Should not scale with number of shares", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// Create and share with multiple users
			users := make([]*client.User, 10)
			for i := 0; i < 10; i++ {
				users[i], err = client.InitUser(fmt.Sprintf("user%d", i), defaultPassword)
				Expect(err).To(BeNil())
			}

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			for i := 0; i < 10; i++ {
				invite, err := alice.CreateInvitation(aliceFile, fmt.Sprintf("user%d", i))
				Expect(err).To(BeNil())
				err = users[i].AcceptInvitation("alice", invite, fmt.Sprintf("file%d", i))
				Expect(err).To(BeNil())
			}

			// Append bandwidth should not depend on number of shares
			bw := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("X"))
			Expect(err).To(BeNil())
			bw = userlib.DatastoreGetBandwidth() - bw

			Expect(bw).To(BeNumerically("<", 10000))
		})
	})

	Describe("File Integrity Testing", func() {
		Specify("Integrity Test: Testing detection of file data tampering.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Verifying Alice can load the file normally.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Simulating adversary tampering with file data in datastore.")
			datastoreMap := userlib.DatastoreGetMap()

			// Tamper with the first entry in the datastore
			for key, value := range datastoreMap {
				if len(value) > 0 {
					value[0] ^= 0x01 // Flip a bit to corrupt the data
					userlib.DatastoreSet(key, value)
					userlib.DebugMsg("Tampered with datastore entry")
				}
			}

			userlib.DebugMsg("Attempting to load file after tampering - should detect integrity violation.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil(), "LoadFile should fail due to integrity check failure")
		})
	})
})
