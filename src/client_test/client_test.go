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

	Describe("user authentication tests", func() {
		
		Specify("usernames are case-sensitive", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceUpper, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			// both should be different users
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

		Specify("special characters in username work fine", func() {
			_, err = client.InitUser("alice@email.com", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.InitUser("user-name_123", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.InitUser("user with spaces", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("empty password should work", func() {
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

		Specify("long username and password", func() {
			longUsername := strings.Repeat("a", 1000)
			longPassword := strings.Repeat("p", 1000)

			alice, err = client.InitUser(longUsername, longPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser(longUsername, longPassword)
			Expect(err).To(BeNil())
		})

		Specify("cant change password by reinitializing", func() {
			alice, err = client.InitUser("alice", "password1")
			Expect(err).To(BeNil())

			// try to "change" password by creating user again
			_, err = client.InitUser("alice", "password2")
			Expect(err).ToNot(BeNil())

			// original password should still work
			aliceLaptop, err = client.GetUser("alice", "password1")
			Expect(err).To(BeNil())

			// new password should not work
			_, err = client.GetUser("alice", "password2")
			Expect(err).ToNot(BeNil())
		})

		Specify("wrong password should fail", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			// try with wrong password
			_, err = client.GetUser("alice", "wrongpassword")
			Expect(err).ToNot(BeNil(), "should fail with wrong password")
		})

		Specify("multiple concurrent sessions for same user", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// all sessions should be independent but see same data
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

		Specify("concurrent sessions can modify same file", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			// both sessions append
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
			
			// both should see all appends
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(string(data)).To(ContainSubstring(contentOne))
			Expect(string(data)).To(ContainSubstring(contentTwo))
			Expect(string(data)).To(ContainSubstring(contentThree))
		})
	})

	Describe("file operations tests", func() {
		
		Specify("empty filename is valid", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("special characters in filename", func() {
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

		Specify("very long filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			longFilename := strings.Repeat("a", 10000)

			err = alice.StoreFile(longFilename, []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(longFilename)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("binary file content", func() {
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

		Specify("file with null bytes", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			contentWithNulls := []byte("content\x00with\x00null\x00bytes")

			err = alice.StoreFile(aliceFile, contentWithNulls)
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal(contentWithNulls))
		})

		Specify("empty file content works", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())
			
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("")))
		})

		Specify("storefile completely overwrites including previous appends", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			// overwrite entire file
			err = alice.StoreFile(aliceFile, []byte("new content"))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("new content")))
		})

		Specify("overwrite file multiple times", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			// store and overwrite multiple times
			for i := 0; i < 10; i++ {
				content := fmt.Sprintf("version %d", i)
				err = alice.StoreFile(aliceFile, []byte(content))
				Expect(err).To(BeNil())
			}
			
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("version 9")))
		})

		Specify("multiple users, multiple files each", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// alice creates multiple files
			for i := 0; i < 10; i++ {
				filename := fmt.Sprintf("alice_file_%d.txt", i)
				err = alice.StoreFile(filename, []byte(fmt.Sprintf("alice content %d", i)))
				Expect(err).To(BeNil())
			}

			// bob creates multiple files
			for i := 0; i < 10; i++ {
				filename := fmt.Sprintf("bob_file_%d.txt", i)
				err = bob.StoreFile(filename, []byte(fmt.Sprintf("bob content %d", i)))
				Expect(err).To(BeNil())
			}

			// verify all files
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

		Specify("load file that doesn't exist should error", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			_, err = alice.LoadFile("nonexistent.txt")
			Expect(err).ToNot(BeNil(), "should error on non-existent file")
		})
		
		Specify("append to file that doesn't exist should error", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.AppendToFile("nonexistent.txt", []byte(contentOne))
			Expect(err).ToNot(BeNil(), "should error on non-existent file")
		})
	})

	Describe("sharing and invitation tests", func() {
		
		Specify("create invitation for non-existent recipient fails", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			// try to invite non-existent user
			_, err = alice.CreateInvitation(aliceFile, "nonexistent")
			Expect(err).ToNot(BeNil(), "should fail for non-existent user")
		})
		
		Specify("create invitation for non-existent file fails", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			// try to create invite for file that doesn't exist
			_, err = alice.CreateInvitation("nonexistent.txt", "bob")
			Expect(err).ToNot(BeNil(), "should fail for non-existent file")
		})

		Specify("accept invitation for non-existent file fails", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// delete the file
			datastoreMap := userlib.DatastoreGetMap()
			for key := range datastoreMap {
				userlib.DatastoreDelete(key)
			}
			
			// bob tries to accept
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil(), "should fail when file deleted")
		})

		Specify("acceptinvitation verifies sender identity", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			err = charles.StoreFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())
			
			// alice creates invitation for bob
			inviteFromAlice, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// bob tries to accept alice's invite but claims it's from charles (wrong sender)
			err = bob.AcceptInvitation("charles", inviteFromAlice, bobFile)
			Expect(err).ToNot(BeNil(), "should error when sender identity is wrong")
			
			// bob should be able to accept with correct sender
			err = bob.AcceptInvitation("alice", inviteFromAlice, bobFile)
			Expect(err).To(BeNil())
			
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})
		
		Specify("multiple users share with same recipient", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			
			// alice and bob both create files and share with charles
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			
			invite1, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			
			invite2, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			
			// charles accepts both
			err = charles.AcceptInvitation("alice", invite1, charlesFile)
			Expect(err).To(BeNil())
			
			err = charles.AcceptInvitation("bob", invite2, "charlesFile2")
			Expect(err).To(BeNil())
			
			// verify both work
			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			
			data, err = charles.LoadFile("charlesFile2")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("verify single copy of file exists (no duplication)", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			
			// alice creates and shares with bob
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			err = bob.AcceptInvitation("alice", invite1, bobFile)
			Expect(err).To(BeNil())
			
			// bob shares with charles
			invite2, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			
			err = charles.AcceptInvitation("bob", invite2, charlesFile)
			Expect(err).To(BeNil())
			
			// all three users append different content
			err = alice.AppendToFile(aliceFile, []byte(" alice1"))
			Expect(err).To(BeNil())
			
			err = bob.AppendToFile(bobFile, []byte(" bob1"))
			Expect(err).To(BeNil())
			
			err = charles.AppendToFile(charlesFile, []byte(" charles1"))
			Expect(err).To(BeNil())
			
			// all should see ALL appends (proving single copy)
			expectedFinal := contentOne + " alice1 bob1 charles1"
			
			dataAlice, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(dataAlice).To(Equal([]byte(expectedFinal)))
			
			dataBob, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(dataBob).To(Equal([]byte(expectedFinal)))
			
			dataCharles, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(dataCharles).To(Equal([]byte(expectedFinal)))
			
			// now alice overwrites - everyone should see the overwrite
			err = alice.StoreFile(aliceFile, []byte("completely new content"))
			Expect(err).To(BeNil())
			
			dataBob2, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(dataBob2).To(Equal([]byte("completely new content")))
			
			dataCharles2, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(dataCharles2).To(Equal([]byte("completely new content")))
		})

		Specify("cannot accept invitation if filename already exists", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			// bob already has a file with this name
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			
			// alice tries to share with bob using a filename bob already has
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// bob tries to accept with a filename he already has
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil(), "should error when accepting with existing filename")
			
			// bob's original file should still be intact
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("accept same invitation twice", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// accept once
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			
			// try to accept again - behavior is undefined but shouldn't panic
			err = bob.AcceptInvitation("alice", invite, "bobFile2")
			// may succeed or fail, but shouldn't panic
		})
	})
	
	Describe("revocation tests", func() {
		
		Specify("revoke before invitation accepted", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// revoke BEFORE bob accepts
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// bob should not be able to accept revoked invitation
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil(), "should not accept invitation after revocation")
		})
		
		Specify("multiple revocations on same user", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			
			// first revocation
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// second revocation should either succeed or error gracefully
			err = alice.RevokeAccess(aliceFile, "bob")
			// either outcome is acceptable for undefined behavior
		})
		
		Specify("revoked user cannot create invitations", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			
			// revoke bob
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// bob should not be able to create invitation
			_, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil(), "revoked user should not create invitations")
		})
		
		Specify("verify file re-encryption after revoke", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			
			// bob saves some uuids
			beforeRevoke := userlib.DatastoreGetMap()
			savedData := make(map[userlib.UUID][]byte)
			for k, v := range beforeRevoke {
				savedData[k] = append([]byte{}, v...)
			}
			
			// alice revokes bob
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// alice appends - should use new encryption
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			
			// bob tries to use saved data - should fail
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil(), "revoked user should not access file with old data")
		})
		
		Specify("revoked user with saved uuids cannot read", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			
			// bob can load initially
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			
			// revoke bob
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// bob should not be able to load anymore
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil(), "revoked user should not access file")
		})

		Specify("revoked user cannot detect future updates", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			
			// bob takes a snapshot of datastore before revocation
			beforeRevoke := userlib.DatastoreGetMap()
			beforeKeys := make(map[userlib.UUID][]byte)
			for k, v := range beforeRevoke {
				beforeKeys[k] = append([]byte{}, v...)
			}
			
			// alice revokes bob
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// take another snapshot after revocation
			afterRevoke := userlib.DatastoreGetMap()
			afterKeys := make(map[userlib.UUID][]byte)
			for k, v := range afterRevoke {
				afterKeys[k] = append([]byte{}, v...)
			}
			
			// alice makes several updates
			for i := 0; i < 5; i++ {
				err = alice.AppendToFile(aliceFile, []byte(fmt.Sprintf(" update%d", i)))
				Expect(err).To(BeNil())
			}
			
			// the uuids that changed should be encrypted/inaccessible to bob
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil(), "bob should not access file after revocation")
			
			// verify alice can still access with all updates
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			expectedContent := contentOne + " update0 update1 update2 update3 update4"
			Expect(data).To(Equal([]byte(expectedContent)))
		})
	})

	Describe("integrity and security tests", func() {
		
		Specify("detect file data tampering", func() {
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

			for key, value := range datastoreMap {
				if len(value) > 0 {
					value[0] ^= 0x01 // flip a bit to corrupt the data
					userlib.DatastoreSet(key, value)
					userlib.DebugMsg("Tampered with datastore entry")
				}
			}

			userlib.DebugMsg("Attempting to load file after tampering - should detect integrity violation.")
			data, err = alice.LoadFile(aliceFile)

			if err != nil {
				userlib.DebugMsg("Integrity check detected tampering (error returned).")
				Expect(err).ToNot(BeNil())
			} else {
				userlib.DebugMsg("No error returned - checking if data was corrupted.")
				Expect(data).ToNot(Equal([]byte(contentOne)),
					"data should be corrupted after tampering if no integrity check exists")
			}
		})

		Specify("detect invite tampering", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file and creating invite for Bob.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Tampering with the invite by modifying datastore.")
			// instead of tampering with the uuid, tamper with what it points to
			inviteData, ok := userlib.DatastoreGet(invite)
			Expect(ok).To(BeTrue(), "invite data should exist in datastore")

			// corrupt the invite data
			if len(inviteData) > 0 {
				inviteData[0] ^= 0x01 // flip a bit
				userlib.DatastoreSet(invite, inviteData)
			}

			userlib.DebugMsg("Bob attempting to accept tampered invite - should fail.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil(), "acceptinvitation should reject tampered invite data")
		})
		
		Specify("detect user data tampering", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			// tamper with user data in datastore
			datastoreMap := userlib.DatastoreGetMap()
			for key, value := range datastoreMap {
				if len(value) > 10 { 
					value[5] ^= 0xFF // corrupt middle of data
					userlib.DatastoreSet(key, value)
					break
				}
			}
			
			// try to get user again - should detect tampering
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil(), "should detect user data tampering")
		})
		
		Specify("detect file metadata tampering", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			// save datastore state
			originalMap := make(map[userlib.UUID][]byte)
			datastoreMap := userlib.DatastoreGetMap()
			for k, v := range datastoreMap {
				originalMap[k] = append([]byte{}, v...)
			}
			
			// append to create metadata
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			
			// find and tamper with newly created structures
			datastoreMap = userlib.DatastoreGetMap()
			for key, value := range datastoreMap {
				if _, existed := originalMap[key]; !existed { // likely metadata
					if len(value) > 0 {
						value[len(value)-1] ^= 0x01
						userlib.DatastoreSet(key, value)
					}
				}
			}
			
			// should detect tampering on next operation
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil(), "should detect metadata tampering")
		})
		
		Specify("detect append structure tampering", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			
			// tamper with random datastore entries
			datastoreMap := userlib.DatastoreGetMap()
			count := 0
			for key, value := range datastoreMap {
				if len(value) > 10 {
					value[3] ^= 0xFF
					userlib.DatastoreSet(key, value)
					count++
					if count >= 3 {
						break
					}
				}
			}
			
			// should detect when loading or appending
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			if err == nil {
				_, err = alice.LoadFile(aliceFile)
			}
			Expect(err).ToNot(BeNil(), "should detect tampering in append structure")
		})
		
		Specify("delete random datastore entries", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			// delete some entries
			datastoreMap := userlib.DatastoreGetMap()
			count := 0
			for key := range datastoreMap {
				userlib.DatastoreDelete(key)
				count++
				if count >= 2 {
					break
				}
			}
			
			// should fail to load
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil(), "should detect deleted data")
		})

		Specify("filename length confidentiality", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			// create files with very different filename lengths
			shortName := "a"
			longName := strings.Repeat("verylongfilename", 50) // 800 characters
			
			// store files with different length names but same content
			err = alice.StoreFile(shortName, []byte(contentOne))
			Expect(err).To(BeNil())
			
			// capture datastore state
			before := userlib.DatastoreGetMap()
			beforeSize := 0
			for _, v := range before {
				beforeSize += len(v)
			}
			
			err = bob.StoreFile(longName, []byte(contentOne))
			Expect(err).To(BeNil())
			
			// capture datastore state after
			after := userlib.DatastoreGetMap()
			afterSize := 0
			for _, v := range after {
				afterSize += len(v)
			}
			
			// both should be able to load successfully
			dataShort, err := alice.LoadFile(shortName)
			Expect(err).To(BeNil())
			Expect(dataShort).To(Equal([]byte(contentOne)))
			
			dataLong, err := bob.LoadFile(longName)
			Expect(err).To(BeNil())
			Expect(dataLong).To(Equal([]byte(contentOne)))
			
			// test with sharing - filename length still shouldn't leak
			invite, err := alice.CreateInvitation(shortName, "bob")
			Expect(err).To(BeNil())
			
			err = bob.AcceptInvitation("alice", invite, longName+"_shared")
			Expect(err).To(BeNil())
			
			dataShared, err := bob.LoadFile(longName + "_shared")
			Expect(err).To(BeNil())
			Expect(dataShared).To(Equal([]byte(contentOne)))
		})
	})

	Describe("append efficiency tests", func() {

		Specify("multiple appends should use constant bandwidth", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// measure bandwidth for first append
			bw1 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("X"))
			Expect(err).To(BeNil())
			bw1 = userlib.DatastoreGetBandwidth() - bw1

			// append many more times
			for i := 0; i < 100; i++ {
				err = alice.AppendToFile(aliceFile, []byte("X"))
				Expect(err).To(BeNil())
			}

			// measure bandwidth for 102nd append
			bw2 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("X"))
			Expect(err).To(BeNil())
			bw2 = userlib.DatastoreGetBandwidth() - bw2

			// bandwidth should be approximately the same
			Expect(bw2).To(BeNumerically("~", bw1, float64(bw1)*0.1))
		})

		Specify("empty append should use minimal bandwidth", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bw := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())
			bw = userlib.DatastoreGetBandwidth() - bw

			// should use minimal bandwidth (just overhead, no actual content)
			Expect(bw).To(BeNumerically("<", 5000))
		})

		Specify("should not scale with previous append size", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("initial"))
			Expect(err).To(BeNil())

			// append huge amount of data
			hugeContent := make([]byte, 1000000)
			err = alice.AppendToFile(aliceFile, hugeContent)
			Expect(err).To(BeNil())

			// next small append should not download the huge content
			bw := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("small"))
			Expect(err).To(BeNil())
			bw = userlib.DatastoreGetBandwidth() - bw

			// should be small, not proportional to 1mb
			Expect(bw).To(BeNumerically("<", 10000))
		})

		Specify("should not scale with number of shares", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// create and share with multiple users
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

			// append bandwidth should not depend on number of shares
			bw := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("X"))
			Expect(err).To(BeNil())
			bw = userlib.DatastoreGetBandwidth() - bw

			Expect(bw).To(BeNumerically("<", 10000))
		})

		Specify("diagnostic - multiple same-size appends should use consistent bandwidth", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte("initial"))
			Expect(err).To(BeNil())
			
			var bandwidths []int
			for i := 1; i <= 3; i++ {
				bw := userlib.DatastoreGetBandwidth()
				err = alice.AppendToFile(aliceFile, []byte("X"))
				Expect(err).To(BeNil())
				bw = userlib.DatastoreGetBandwidth() - bw
				bandwidths = append(bandwidths, bw)
			}
			
			// check that bandwidth doesn't grow with number of appends
			// allow 20% variance for overhead
			Expect(bandwidths[1]).To(BeNumerically("~", bandwidths[0], float64(bandwidths[0])*0.2))
			Expect(bandwidths[2]).To(BeNumerically("~", bandwidths[0], float64(bandwidths[0])*0.2))
		})
		
		Specify("diagnostic - bandwidth should scale with content size", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte("initial"))
			Expect(err).To(BeNil())
			
			bw1 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("0123456789")) // 10 bytes
			Expect(err).To(BeNil())
			bw1 = userlib.DatastoreGetBandwidth() - bw1
			
			content100 := make([]byte, 100)
			bw2 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, content100) // 100 bytes
			Expect(err).To(BeNil())
			bw2 = userlib.DatastoreGetBandwidth() - bw2
			
			content1000 := make([]byte, 1000)
			bw3 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, content1000) // 1000 bytes
			Expect(err).To(BeNil())
			bw3 = userlib.DatastoreGetBandwidth() - bw3
			
			// bandwidth should grow with content size
			diff1 := bw2 - bw1
			diff2 := bw3 - bw2
			
			Expect(diff1).To(BeNumerically(">", 50))
			Expect(diff2).To(BeNumerically(">", 500))
			Expect(diff2).To(BeNumerically(">", diff1))
		})
		
		Specify("diagnostic - previous append size should not matter", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile(aliceFile, []byte("initial"))
			Expect(err).To(BeNil())
			
			// append 1kb
			content1KB := make([]byte, 1000)
			err = alice.AppendToFile(aliceFile, content1KB)
			Expect(err).To(BeNil())
			
			// then append 1 byte
			bw1 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("X"))
			Expect(err).To(BeNil())
			bw1 = userlib.DatastoreGetBandwidth() - bw1
			
			// append 100kb
			content100KB := make([]byte, 100000)
			err = alice.AppendToFile(aliceFile, content100KB)
			Expect(err).To(BeNil())
			
			// then append 1 byte again
			bw2 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte("Y"))
			Expect(err).To(BeNil())
			bw2 = userlib.DatastoreGetBandwidth() - bw2
			
			// bandwidth should be similar regardless of previous append size
			// allow 20% variance
			Expect(bw2).To(BeNumerically("~", bw1, float64(bw1)*0.2))
		})
		
		Specify("diagnostic - file size should not affect append bandwidth", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			err = alice.StoreFile("small.txt", []byte("tiny"))
			Expect(err).To(BeNil())
			
			bwSmall := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile("small.txt", []byte("X"))
			Expect(err).To(BeNil())
			bwSmall = userlib.DatastoreGetBandwidth() - bwSmall
			
			largeContent := make([]byte, 100000)
			err = alice.StoreFile("large.txt", largeContent)
			Expect(err).To(BeNil())
			
			bwLarge := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile("large.txt", []byte("X"))
			Expect(err).To(BeNil())
			bwLarge = userlib.DatastoreGetBandwidth() - bwLarge
			
			// bandwidth should be similar regardless of file size
			// allow 20% variance
			Expect(bwLarge).To(BeNumerically("~", bwSmall, float64(bwSmall)*0.2))
		})
	})
})
