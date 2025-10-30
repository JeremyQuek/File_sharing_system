package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	"encoding/hex"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	//"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	//"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const CHUNK_SIZE = 4096 // 4KB chunks for efficient append

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// User metadata stored at deterministic UUID (plaintext)
type UserMetadata struct {
	Salt           []byte
	UserStructUUID uuid.UUID
}

// User's encrypted file namespace
type UserStruct struct {
	Files      map[string]FilePointers // hashed filename -> pointers
	PrivEncKey userlib.PKEDecKey       // RSA private key (encrypted in datastore)
	SignKey    userlib.DSSignKey       // DSA signing key (encrypted in datastore)
}

type FilePointers struct {
	FileStructUUID uuid.UUID
	InvStructUUID  uuid.UUID
}

// File structure
type FileStruct struct {
	ContentUUID uuid.UUID
	AccessUUID  uuid.UUID
}

type FileContent struct {
	HeadUUID uuid.UUID
	TailUUID uuid.UUID
}

type FileChunkContent struct {
	EncryptedContent []byte
	NextUUID         *uuid.UUID // nil if last chunk
}

// Access control tree
type FileAccess struct {
	OwnerNodeUUID uuid.UUID
}

type FileAccessNode struct {
	Username       string     // Plaintext username (encrypted with file keys anyway)
	HashedUsername []byte
	InvStructUUID  uuid.UUID
	ShareeUUIDs    []uuid.UUID // list of child nodes
}

// Invitation structure
type InvStruct struct {
	FileStructUUID uuid.UUID
	FileEncKey     []byte
	FileMACKey     []byte
	SharerNodeUUID uuid.UUID
	SharerUsername string // Username of person who created this invitation
}

// Wrapper for hybrid encryption
type HybridInvStruct struct {
	RSAEncryptedSymKey    []byte
	SymEncryptedInvStruct []byte
	Signature             []byte // Digital signature by sender to prove authenticity
}

// User struct for holding session data
type User struct {
	Username   string
	Password   string
	PrivEncKey userlib.PKEDecKey
	SignKey    userlib.DSSignKey
}

// ============================================================================
// HELPER FUNCTIONS - UUID GENERATION
// ============================================================================

func deterministicUUID(input string) uuid.UUID {
	hash := userlib.Hash([]byte(input))
	deterministicUUID, _ := uuid.FromBytes(hash[:16])
	return deterministicUUID
}

func getUserMetadataUUID(username string) uuid.UUID {
	return deterministicUUID("user-metadata/" + username)
}

func getUserStructUUID(username string) uuid.UUID {
	return deterministicUUID("user-struct/" + username)
}

func getFileStructUUID(ownerUsername, filename string) uuid.UUID {
	return deterministicUUID("file-struct/" + ownerUsername + "/" + filename)
}

func getFileAccessNodeUUID(username string, fileUUID uuid.UUID) uuid.UUID {
	return deterministicUUID("file-access-node/" + username + "/" + fileUUID.String())
}

func getInvStructUUID(username string, fileUUID uuid.UUID) uuid.UUID {
	return deterministicUUID("inv-struct/" + username + "/" + fileUUID.String())
}

func hashFilename(filename string) string {
	hash := userlib.Hash([]byte(filename))
	return hex.EncodeToString(hash)
}

// ============================================================================
// HELPER FUNCTIONS - KEY DERIVATION
// ============================================================================

func deriveUserKeys(password string, salt []byte) (encKey, macKey []byte, err error) {
	// Generate master key using Argon2
	masterKey := userlib.Argon2Key([]byte(password), salt, 16)
	
	// Derive encryption and MAC keys using HKDF
	encKey, err = userlib.HashKDF(masterKey, []byte("encryption"))
	if err != nil {
		return nil, nil, err
	}
	encKey = encKey[:16]
	
	macKey, err = userlib.HashKDF(masterKey, []byte("mac"))
	if err != nil {
		return nil, nil, err
	}
	macKey = macKey[:16]
	
	return encKey, macKey, nil
}

func deriveFileKeys() (encKey, macKey []byte) {
	// Generate random keys for file encryption and MAC
	encKey = userlib.RandomBytes(16)
	macKey = userlib.RandomBytes(16)
	return encKey, macKey
}

// ============================================================================
// HELPER FUNCTIONS - ENCRYPTION/DECRYPTION
// ============================================================================

func encryptThenMAC(data, encKey, macKey []byte) ([]byte, error) {
	// Encrypt data
	iv := userlib.RandomBytes(16)
	encrypted := userlib.SymEnc(encKey, iv, data)
	
	// MAC the encrypted data
	mac, err := userlib.HMACEval(macKey, encrypted)
	if err != nil {
		return nil, err
	}
	
	// Concatenate: MAC || encrypted data
	result := append(mac, encrypted...)
	return result, nil
}

func verifyMACThenDecrypt(data, encKey, macKey []byte) ([]byte, error) {
	// Check minimum length
	if len(data) < 64 {
		return nil, errors.New("data too short")
	}
	
	// Split MAC and encrypted data
	mac := data[:64]
	encrypted := data[64:]
	
	// Verify MAC
	expectedMAC, err := userlib.HMACEval(macKey, encrypted)
	if err != nil {
		return nil, err
	}
	
	if !userlib.HMACEqual(mac, expectedMAC) {
		return nil, errors.New("MAC verification failed")
	}
	
	// Decrypt data
	decrypted := userlib.SymDec(encKey, encrypted)
	return decrypted, nil
}

// ============================================================================
// HELPER FUNCTIONS - HYBRID ENCRYPTION FOR INVSTRUCT
// ============================================================================

func hybridEncrypt(invStruct *InvStruct, recipientPubKey userlib.PKEEncKey, senderSignKey userlib.DSSignKey) (*HybridInvStruct, error) {
	// 1. Generate random symmetric key
	symKey := userlib.RandomBytes(16)
	
	// 2. Derive enc/mac keys from symmetric key
	encKey, err := userlib.HashKDF(symKey, []byte("inv-enc"))
	if err != nil {
		return nil, err
	}
	encKey = encKey[:16]
	
	macKey, err := userlib.HashKDF(symKey, []byte("inv-mac"))
	if err != nil {
		return nil, err
	}
	macKey = macKey[:16]
	
	// 3. Marshal and encrypt InvStruct
	invBytes, err := json.Marshal(invStruct)
	if err != nil {
		return nil, err
	}
	
	encryptedInv, err := encryptThenMAC(invBytes, encKey, macKey)
	if err != nil {
		return nil, err
	}
	
	// 4. RSA encrypt symmetric key
	rsaEncryptedKey, err := userlib.PKEEnc(recipientPubKey, symKey)
	if err != nil {
		return nil, err
	}
	
	// 5. Sign the encrypted invitation to prove sender identity
	// Sign over both the RSA encrypted key and the symmetric encrypted invitation
	toSign := append(rsaEncryptedKey, encryptedInv...)
	signature, err := userlib.DSSign(senderSignKey, toSign)
	if err != nil {
		return nil, err
	}
	
	return &HybridInvStruct{
		RSAEncryptedSymKey:    rsaEncryptedKey,
		SymEncryptedInvStruct: encryptedInv,
		Signature:             signature,
	}, nil
}

func hybridDecrypt(hybridInv *HybridInvStruct, recipientPrivKey userlib.PKEDecKey, senderVerifyKey userlib.DSVerifyKey) (*InvStruct, error) {
	// 1. Verify signature first to authenticate sender
	toVerify := append(hybridInv.RSAEncryptedSymKey, hybridInv.SymEncryptedInvStruct...)
	err := userlib.DSVerify(senderVerifyKey, toVerify, hybridInv.Signature)
	if err != nil {
		return nil, errors.New("signature verification failed - invitation not from claimed sender")
	}
	
	// 2. RSA decrypt symmetric key
	symKey, err := userlib.PKEDec(recipientPrivKey, hybridInv.RSAEncryptedSymKey)
	if err != nil {
		return nil, err
	}
	
	// 3. Derive enc/mac keys from symmetric key
	encKey, err := userlib.HashKDF(symKey, []byte("inv-enc"))
	if err != nil {
		return nil, err
	}
	encKey = encKey[:16]
	
	macKey, err := userlib.HashKDF(symKey, []byte("inv-mac"))
	if err != nil {
		return nil, err
	}
	macKey = macKey[:16]
	
	// 4. Verify MAC and decrypt InvStruct
	invBytes, err := verifyMACThenDecrypt(hybridInv.SymEncryptedInvStruct, encKey, macKey)
	if err != nil {
		return nil, err
	}
	
	// 5. Unmarshal InvStruct
	var invStruct InvStruct
	err = json.Unmarshal(invBytes, &invStruct)
	if err != nil {
		return nil, err
	}
	
	return &invStruct, nil
}

// Helper function to decrypt invitation and automatically get sharer's verify key
// Note: We decrypt first to get SharerUsername, then verify signature
// This is secure because signature verification will fail if data is tampered
func decryptInvitation(hybridInv *HybridInvStruct, recipientPrivKey userlib.PKEDecKey) (*InvStruct, error) {
	// Decrypt to get the SharerUsername
	symKey, err := userlib.PKEDec(recipientPrivKey, hybridInv.RSAEncryptedSymKey)
	if err != nil {
		return nil, err
	}
	
	encKey, err := userlib.HashKDF(symKey, []byte("inv-enc"))
	if err != nil {
		return nil, err
	}
	encKey = encKey[:16]
	
	macKey, err := userlib.HashKDF(symKey, []byte("inv-mac"))
	if err != nil {
		return nil, err
	}
	macKey = macKey[:16]
	
	invBytes, err := verifyMACThenDecrypt(hybridInv.SymEncryptedInvStruct, encKey, macKey)
	if err != nil {
		return nil, err
	}
	
	var invStruct InvStruct
	err = json.Unmarshal(invBytes, &invStruct)
	if err != nil {
		return nil, err
	}
	
	// Now verify the signature using sharer's verify key
	sharerVerifyKey, ok := userlib.KeystoreGet(invStruct.SharerUsername + "_verify")
	if !ok {
		return nil, errors.New("sharer's verify key not found")
	}
	
	// Verify signature
	toVerify := append(hybridInv.RSAEncryptedSymKey, hybridInv.SymEncryptedInvStruct...)
	err = userlib.DSVerify(sharerVerifyKey, toVerify, hybridInv.Signature)
	if err != nil {
		return nil, errors.New("signature verification failed - invitation tampered or not from claimed sharer")
	}
	
	return &invStruct, nil
}

// ============================================================================
// HELPER FUNCTIONS - STORAGE AND RETRIEVAL
// ============================================================================

func storeUserStruct(username, password string, userStruct *UserStruct) error {
	// Get user metadata
	userMetaUUID := getUserMetadataUUID(username)
	userMetaBytes, ok := userlib.DatastoreGet(userMetaUUID)
	if !ok {
		return errors.New("user metadata not found")
	}
	
	var userMeta UserMetadata
	err := json.Unmarshal(userMetaBytes, &userMeta)
	if err != nil {
		return err
	}
	
	// Derive keys
	encKey, macKey, err := deriveUserKeys(password, userMeta.Salt)
	if err != nil {
		return err
	}
	
	// Marshal UserStruct (no internal MAC needed)
	userStructBytes, err := json.Marshal(userStruct)
	if err != nil {
		return err
	}
	
	// Encrypt and MAC - this provides integrity protection
	encrypted, err := encryptThenMAC(userStructBytes, encKey, macKey)
	if err != nil {
		return err
	}
	
	userlib.DatastoreSet(userMeta.UserStructUUID, encrypted)
	return nil
}

func loadUserStruct(username, password string) (*UserStruct, error) {
	// Get user metadata
	userMetaUUID := getUserMetadataUUID(username)
	userMetaBytes, ok := userlib.DatastoreGet(userMetaUUID)
	if !ok {
		return nil, errors.New("user not found")
	}
	
	var userMeta UserMetadata
	err := json.Unmarshal(userMetaBytes, &userMeta)
	if err != nil {
		return nil, err
	}
	
	// Derive keys
	encKey, macKey, err := deriveUserKeys(password, userMeta.Salt)
	if err != nil {
		return nil, err
	}
	
	// Get encrypted UserStruct
	encryptedData, ok := userlib.DatastoreGet(userMeta.UserStructUUID)
	if !ok {
		return nil, errors.New("user struct not found")
	}
	
	// Verify MAC and decrypt - this verifies integrity
	userStructBytes, err := verifyMACThenDecrypt(encryptedData, encKey, macKey)
	if err != nil {
		return nil, errors.New("authentication failed - wrong password or data tampered")
	}
	
	// Unmarshal UserStruct
	var userStruct UserStruct
	err = json.Unmarshal(userStructBytes, &userStruct)
	if err != nil {
		return nil, err
	}
	
	// Ensure Files map is not nil (JSON unmarshals empty object as nil)
	if userStruct.Files == nil {
		userStruct.Files = make(map[string]FilePointers)
	}
	
	return &userStruct, nil
}

// ============================================================================
// INIT USER
// ============================================================================

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check for empty username
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	
	// Check if user already exists
	userMetaUUID := getUserMetadataUUID(username)
	if _, ok := userlib.DatastoreGet(userMetaUUID); ok {
		return nil, errors.New("user already exists")
	}
	
	// Generate RSA and DSA keypairs
	pubEncKey, privEncKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	
	// Store public keys in Keystore
	err = userlib.KeystoreSet(username+"_enc", pubEncKey)
	if err != nil {
		return nil, err
	}
	
	err = userlib.KeystoreSet(username+"_verify", verifyKey)
	if err != nil {
		return nil, err
	}
	
	// Generate salt
	salt := userlib.RandomBytes(16)
	
	// Derive encryption and MAC keys
	encKey, macKey, err := deriveUserKeys(password, salt)
	if err != nil {
		return nil, err
	}
	
	// Create UserStruct with private keys
	userStruct := &UserStruct{
		Files:      make(map[string]FilePointers),
		PrivEncKey: privEncKey,
		SignKey:    signKey,
	}
	
	// Marshal UserStruct (no internal MAC)
	userStructBytes, err := json.Marshal(userStruct)
	if err != nil {
		return nil, err
	}
	
	// Encrypt UserStruct with external MAC
	encrypted, err := encryptThenMAC(userStructBytes, encKey, macKey)
	if err != nil {
		return nil, err
	}
	
	// Store UserStruct
	userStructUUID := getUserStructUUID(username)
	userlib.DatastoreSet(userStructUUID, encrypted)
	
	// Create and store UserMetadata
	userMeta := &UserMetadata{
		Salt:           salt,
		UserStructUUID: userStructUUID,
	}
	
	userMetaBytes, err := json.Marshal(userMeta)
	if err != nil {
		return nil, err
	}
	
	userlib.DatastoreSet(userMetaUUID, userMetaBytes)
	
	// Create User session object
	userdata := &User{
		Username:   username,
		Password:   password,
		PrivEncKey: privEncKey,
		SignKey:    signKey,
	}
	
	return userdata, nil
}

// ============================================================================
// GET USER
// ============================================================================

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Check for empty username
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	
	// Try to load UserStruct (this verifies password)
	userStruct, err := loadUserStruct(username, password)
	if err != nil {
		return nil, err
	}
	
	// Create User session object with private keys from UserStruct
	userdata := &User{
		Username:   username,
		Password:   password,
		PrivEncKey: userStruct.PrivEncKey,
		SignKey:    userStruct.SignKey,
	}
	
	return userdata, nil
}

// ============================================================================
// STORE FILE
// ============================================================================

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Load UserStruct
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	
	hashedFilename := hashFilename(filename)
	
	// Check if file already exists
	if _, exists := userStruct.Files[hashedFilename]; exists {
		// File exists - overwrite content
		return userdata.overwriteFile(filename, content, userStruct)
	}
	
	// Create new file
	return userdata.createNewFile(filename, content, userStruct)
}

func (userdata *User) createNewFile(filename string, content []byte, userStruct *UserStruct) error {
	// Generate file encryption and MAC keys
	fileEncKey, fileMACKey := deriveFileKeys()
	
	// Split content into chunks and create linked list
	var headUUID, tailUUID uuid.UUID
	var prevUUID *uuid.UUID = nil
	
	// Split content into CHUNK_SIZE pieces
	for i := 0; i < len(content); i += CHUNK_SIZE {
		end := i + CHUNK_SIZE
		if end > len(content) {
			end = len(content)
		}
		chunkContent := content[i:end]
		
		chunkUUID := uuid.New()
		if i == 0 {
			headUUID = chunkUUID
		}
		tailUUID = chunkUUID
		
		// Encrypt chunk content
		encryptedContent, err := encryptThenMAC(chunkContent, fileEncKey, fileMACKey)
		if err != nil {
			return err
		}
		
		chunk := &FileChunkContent{
			EncryptedContent: encryptedContent,
			NextUUID:         nil,
		}
		
		// Store chunk
		chunkBytes, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(chunkUUID, chunkBytes)
		
		// Update previous chunk's NextUUID
		if prevUUID != nil {
			prevChunkBytes, ok := userlib.DatastoreGet(*prevUUID)
			if !ok {
				return errors.New("previous chunk not found")
			}
			
			var prevChunk FileChunkContent
			err = json.Unmarshal(prevChunkBytes, &prevChunk)
			if err != nil {
				return err
			}
			
			prevChunk.NextUUID = &chunkUUID
			prevChunkBytes, err = json.Marshal(prevChunk)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(*prevUUID, prevChunkBytes)
		}
		
		prevUUID = &chunkUUID
	}
	
	// Handle empty file case
	if len(content) == 0 {
		chunkUUID := uuid.New()
		headUUID = chunkUUID
		tailUUID = chunkUUID
		
		encryptedContent, err := encryptThenMAC([]byte{}, fileEncKey, fileMACKey)
		if err != nil {
			return err
		}
		
		chunk := &FileChunkContent{
			EncryptedContent: encryptedContent,
			NextUUID:         nil,
		}
		
		chunkBytes, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(chunkUUID, chunkBytes)
	}
	
	// Create FileContent
	fileContent := &FileContent{
		HeadUUID: headUUID,
		TailUUID: tailUUID,
	}
	
	// Store FileContent
	fileContentUUID := uuid.New()
	fileContentBytes, err := json.Marshal(fileContent)
	if err != nil {
		return err
	}
	encryptedFileContent, err := encryptThenMAC(fileContentBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileContentUUID, encryptedFileContent)
	
	// Create FileAccessNode for owner
	fileStructUUID := getFileStructUUID(userdata.Username, filename)
	fileAccessNodeUUID := getFileAccessNodeUUID(userdata.Username, fileStructUUID)
	invStructUUID := getInvStructUUID(userdata.Username, fileStructUUID)
	
	hashedUsername := userlib.Hash([]byte(userdata.Username))
	
	fileAccessNode := &FileAccessNode{
		Username:       userdata.Username,
		HashedUsername: hashedUsername,
		InvStructUUID:  invStructUUID,
		ShareeUUIDs:    []uuid.UUID{},
	}
	
	fileAccessNodeBytes, err := json.Marshal(fileAccessNode)
	if err != nil {
		return err
	}
	encryptedNode, err := encryptThenMAC(fileAccessNodeBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileAccessNodeUUID, encryptedNode)
	
	// Create FileAccess
	fileAccess := &FileAccess{
		OwnerNodeUUID: fileAccessNodeUUID,
	}
	
	fileAccessUUID := uuid.New()
	fileAccessBytes, err := json.Marshal(fileAccess)
	if err != nil {
		return err
	}
	encryptedAccess, err := encryptThenMAC(fileAccessBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileAccessUUID, encryptedAccess)
	
	// Create FileStruct
	fileStruct := &FileStruct{
		ContentUUID: fileContentUUID,
		AccessUUID:  fileAccessUUID,
	}
	
	fileStructBytes, err := json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	encryptedFileStruct, err := encryptThenMAC(fileStructBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStructUUID, encryptedFileStruct)
	
	// Create InvStruct for owner
	invStruct := &InvStruct{
		FileStructUUID: fileStructUUID,
		FileEncKey:     fileEncKey,
		FileMACKey:     fileMACKey,
		SharerNodeUUID: fileAccessNodeUUID,
		SharerUsername: userdata.Username,
	}
	
	// Get owner's public key
	ownerPubKey, ok := userlib.KeystoreGet(userdata.Username + "_enc")
	if !ok {
		return errors.New("owner public key not found")
	}
	
	// Hybrid encrypt InvStruct with signature
	hybridInv, err := hybridEncrypt(invStruct, ownerPubKey, userdata.SignKey)
	if err != nil {
		return err
	}
	
	hybridInvBytes, err := json.Marshal(hybridInv)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(invStructUUID, hybridInvBytes)
	
	// Update UserStruct
	hashedFilename := hashFilename(filename)
	userStruct.Files[hashedFilename] = FilePointers{
		FileStructUUID: fileStructUUID,
		InvStructUUID:  invStructUUID,
	}
	
	err = storeUserStruct(userdata.Username, userdata.Password, userStruct)
	if err != nil {
		return err
	}
	
	return nil
}

func (userdata *User) overwriteFile(filename string, content []byte, userStruct *UserStruct) error {
	hashedFilename := hashFilename(filename)
	filePointers := userStruct.Files[hashedFilename]
	
	// Get InvStruct to get keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		return errors.New("invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err := json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return err
	}
	
	// Decrypt and verify invitation
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return err
	}
	
	// Get file encryption and MAC keys
	fileEncKey := invStruct.FileEncKey
	fileMACKey := invStruct.FileMACKey
	
	// Get FileStruct
	fileStructBytes, ok := userlib.DatastoreGet(filePointers.FileStructUUID)
	if !ok {
		return errors.New("file struct not found")
	}
	
	decryptedFileStruct, err := verifyMACThenDecrypt(fileStructBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	
	var fileStruct FileStruct
	err = json.Unmarshal(decryptedFileStruct, &fileStruct)
	if err != nil {
		return err
	}
	
	// Get FileContent
	fileContentBytes, ok := userlib.DatastoreGet(fileStruct.ContentUUID)
	if !ok {
		return errors.New("file content not found")
	}
	
	decryptedFileContent, err := verifyMACThenDecrypt(fileContentBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	
	var fileContent FileContent
	err = json.Unmarshal(decryptedFileContent, &fileContent)
	if err != nil {
		return err
	}
	
	// Delete old chunks (optional - can leave as garbage)
	// For now, we'll just create new chunks and update pointers
	
	// Split content into chunks and create linked list
	var headUUID, tailUUID uuid.UUID
	var prevUUID *uuid.UUID = nil
	
	// Split content into CHUNK_SIZE pieces
	for i := 0; i < len(content); i += CHUNK_SIZE {
		end := i + CHUNK_SIZE
		if end > len(content) {
			end = len(content)
		}
		chunkContent := content[i:end]
		
		chunkUUID := uuid.New()
		if i == 0 {
			headUUID = chunkUUID
		}
		tailUUID = chunkUUID
		
		// Encrypt chunk content
		encryptedContent, err := encryptThenMAC(chunkContent, fileEncKey, fileMACKey)
		if err != nil {
			return err
		}
		
		chunk := &FileChunkContent{
			EncryptedContent: encryptedContent,
			NextUUID:         nil,
		}
		
		// Store chunk
		chunkBytes, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(chunkUUID, chunkBytes)
		
		// Update previous chunk's NextUUID
		if prevUUID != nil {
			prevChunkBytes, ok := userlib.DatastoreGet(*prevUUID)
			if !ok {
				return errors.New("previous chunk not found")
			}
			
			var prevChunk FileChunkContent
			err = json.Unmarshal(prevChunkBytes, &prevChunk)
			if err != nil {
				return err
			}
			
			prevChunk.NextUUID = &chunkUUID
			prevChunkBytes, err = json.Marshal(prevChunk)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(*prevUUID, prevChunkBytes)
		}
		
		prevUUID = &chunkUUID
	}
	
	// Handle empty file case
	if len(content) == 0 {
		chunkUUID := uuid.New()
		headUUID = chunkUUID
		tailUUID = chunkUUID
		
		encryptedContent, err := encryptThenMAC([]byte{}, fileEncKey, fileMACKey)
		if err != nil {
			return err
		}
		
		chunk := &FileChunkContent{
			EncryptedContent: encryptedContent,
			NextUUID:         nil,
		}
		
		chunkBytes, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(chunkUUID, chunkBytes)
	}
	
	// Update FileContent with new head and tail
	fileContent.HeadUUID = headUUID
	fileContent.TailUUID = tailUUID
	
	// Store updated FileContent
	fileContentBytes, err = json.Marshal(fileContent)
	if err != nil {
		return err
	}
	encryptedFileContent, err := encryptThenMAC(fileContentBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStruct.ContentUUID, encryptedFileContent)
	
	return nil
}

// ============================================================================
// APPEND TO FILE
// ============================================================================

func (userdata *User) AppendToFile(filename string, content []byte) error {
	
	if len(content) == 0 {
		return nil
	}
	
	// Load UserStruct
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	
	hashedFilename := hashFilename(filename)
	
	// Check if file exists
	filePointers, exists := userStruct.Files[hashedFilename]
	if !exists {
		return errors.New("file not found")
	}
	
	// Get InvStruct to get keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		return errors.New("invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return err
	}
	
	// Decrypt InvStruct
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return err
	}
	
	fileEncKey := invStruct.FileEncKey
	fileMACKey := invStruct.FileMACKey
	
	// Get FileStruct
	fileStructBytes, ok := userlib.DatastoreGet(filePointers.FileStructUUID)
	if !ok {
		return errors.New("file struct not found")
	}
	
	decryptedFileStruct, err := verifyMACThenDecrypt(fileStructBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	
	var fileStruct FileStruct
	err = json.Unmarshal(decryptedFileStruct, &fileStruct)
	if err != nil {
		return err
	}
	
	// Get FileContent
	fileContentBytes, ok := userlib.DatastoreGet(fileStruct.ContentUUID)
	if !ok {
		return errors.New("file content not found")
	}
	
	decryptedFileContent, err := verifyMACThenDecrypt(fileContentBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	
	var fileContent FileContent
	err = json.Unmarshal(decryptedFileContent, &fileContent)
	if err != nil {
		return err
	}
	
	// Split appended content into chunks (for efficiency)
	// This ensures we don't create giant chunks that slow down future appends
		// Split content into CHUNK_SIZE pieces for efficiency
		var firstNewChunkUUID uuid.UUID
		var lastNewChunkUUID uuid.UUID
		var prevChunkUUID *uuid.UUID = nil
		
		for i := 0; i < len(content); i += CHUNK_SIZE {
			end := i + CHUNK_SIZE
			if end > len(content) {
				end = len(content)
			}
			chunkContent := content[i:end]
			
			newChunkUUID := uuid.New()
			if i == 0 {
				firstNewChunkUUID = newChunkUUID
			}
			lastNewChunkUUID = newChunkUUID
			
			// Encrypt chunk content
			encryptedContent, err := encryptThenMAC(chunkContent, fileEncKey, fileMACKey)
			if err != nil {
				return err
			}
			
			newChunk := &FileChunkContent{
				EncryptedContent: encryptedContent,
				NextUUID:         nil,
			}
			
			// Store new chunk
			newChunkBytes, err := json.Marshal(newChunk)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(newChunkUUID, newChunkBytes)
			
			// Link previous chunk to this one
			if prevChunkUUID != nil {
				prevChunkBytes, ok := userlib.DatastoreGet(*prevChunkUUID)
				if !ok {
					return errors.New("previous new chunk not found")
				}
				
				var prevChunk FileChunkContent
				err = json.Unmarshal(prevChunkBytes, &prevChunk)
				if err != nil {
					return err
				}
				
				prevChunk.NextUUID = &newChunkUUID
				prevChunkBytes, err = json.Marshal(prevChunk)
				if err != nil {
					return err
				}
				userlib.DatastoreSet(*prevChunkUUID, prevChunkBytes)
			}
			
			prevChunkUUID = &newChunkUUID
		}
		
		// Update old tail chunk to point to first new chunk
		oldTailBytes, ok := userlib.DatastoreGet(fileContent.TailUUID)
		if !ok {
			return errors.New("tail chunk not found")
		}
		
		var oldTailChunk FileChunkContent
		err = json.Unmarshal(oldTailBytes, &oldTailChunk)
		if err != nil {
			return err
		}
		
		oldTailChunk.NextUUID = &firstNewChunkUUID
		oldTailChunkBytes, err := json.Marshal(oldTailChunk)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileContent.TailUUID, oldTailChunkBytes)
		
		// Update FileContent tail pointer to last new chunk
		fileContent.TailUUID = lastNewChunkUUID
	
	// Store updated FileContent
	fileContentBytes, err = json.Marshal(fileContent)
	if err != nil {
		return err
	}
	encryptedFileContent, err := encryptThenMAC(fileContentBytes, fileEncKey, fileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStruct.ContentUUID, encryptedFileContent)
	
	return nil
}

// ============================================================================
// LOAD FILE
// ============================================================================

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Load UserStruct
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}
	
	hashedFilename := hashFilename(filename)
	
	// Check if file exists
	filePointers, exists := userStruct.Files[hashedFilename]
	if !exists {
		return nil, errors.New("file not found")
	}
	
	// Get InvStruct to get keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		// File might have been revoked - do lazy update
		delete(userStruct.Files, hashedFilename)
		storeUserStruct(userdata.Username, userdata.Password, userStruct)
		return nil, errors.New("file access revoked or invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return nil, err
	}
	
	// Decrypt InvStruct
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		// Failed to decrypt - likely revoked with new keys
		delete(userStruct.Files, hashedFilename)
		storeUserStruct(userdata.Username, userdata.Password, userStruct)
		return nil, errors.New("file access revoked - decryption failed")
	}
	
	fileEncKey := invStruct.FileEncKey
	fileMACKey := invStruct.FileMACKey
	
	// Get FileStruct
	fileStructBytes, ok := userlib.DatastoreGet(filePointers.FileStructUUID)
	if !ok {
		return nil, errors.New("file struct not found")
	}
	
	decryptedFileStruct, err := verifyMACThenDecrypt(fileStructBytes, fileEncKey, fileMACKey)
	if err != nil {
		return nil, err
	}
	
	var fileStruct FileStruct
	err = json.Unmarshal(decryptedFileStruct, &fileStruct)
	if err != nil {
		return nil, err
	}
	
	// Get FileContent
	fileContentBytes, ok := userlib.DatastoreGet(fileStruct.ContentUUID)
	if !ok {
		return nil, errors.New("file content not found")
	}
	
	decryptedFileContent, err := verifyMACThenDecrypt(fileContentBytes, fileEncKey, fileMACKey)
	if err != nil {
		return nil, err
	}
	
	var fileContent FileContent
	err = json.Unmarshal(decryptedFileContent, &fileContent)
	if err != nil {
		return nil, err
	}
	
	// Traverse linked list of chunks and concatenate content
	var fullContent []byte
	currentUUID := fileContent.HeadUUID
	
	for {
		// Get current chunk
		chunkBytes, ok := userlib.DatastoreGet(currentUUID)
		if !ok {
			return nil, errors.New("chunk not found")
		}
		
		var chunk FileChunkContent
		err = json.Unmarshal(chunkBytes, &chunk)
		if err != nil {
			return nil, err
		}
		
		// Decrypt chunk content (verifyMACThenDecrypt will verify integrity)
		decryptedChunk, err := verifyMACThenDecrypt(chunk.EncryptedContent, fileEncKey, fileMACKey)
		if err != nil {
			return nil, err
		}
		
		// Append to full content
		fullContent = append(fullContent, decryptedChunk...)
		
		// Move to next chunk
		if chunk.NextUUID == nil {
			break
		}
		currentUUID = *chunk.NextUUID
	}
	
	return fullContent, nil
}

// ============================================================================
// CREATE INVITATION
// ============================================================================

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	
	// Check if recipient exists
	recipientPubKey, ok := userlib.KeystoreGet(recipientUsername + "_enc")
	if !ok {
		return uuid.Nil, errors.New("recipient user does not exist")
	}
	
	// Load UserStruct
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return uuid.Nil, err
	}
	
	hashedFilename := hashFilename(filename)
	
	// Check if file exists
	filePointers, exists := userStruct.Files[hashedFilename]
	if !exists {
		return uuid.Nil, errors.New("file not found in personal namespace")
	}
	
	// Get InvStruct to get file keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		return uuid.Nil, errors.New("invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return uuid.Nil, err
	}
	
	// Decrypt InvStruct
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return uuid.Nil, err
	}
	
	fileEncKey := invStruct.FileEncKey
	fileMACKey := invStruct.FileMACKey
	fileStructUUID := invStruct.FileStructUUID
	
	// Verify I still have valid access by checking if I can decrypt the FileStruct
	fileStructBytes, ok := userlib.DatastoreGet(fileStructUUID)
	if !ok {
		// Remove from my namespace since file no longer exists
		delete(userStruct.Files, hashedFilename)
		storeUserStruct(userdata.Username, userdata.Password, userStruct)
		return uuid.Nil, errors.New("file no longer exists")
	}
	
	_, err = verifyMACThenDecrypt(fileStructBytes, fileEncKey, fileMACKey)
	if err != nil {
		// My access has been revoked - remove from namespace
		delete(userStruct.Files, hashedFilename)
		storeUserStruct(userdata.Username, userdata.Password, userStruct)
		return uuid.Nil, errors.New("access has been revoked - cannot create invitation")
	}
	
	// Get my FileAccessNode UUID
	myNodeUUID := getFileAccessNodeUUID(userdata.Username, fileStructUUID)
	
	// Create FileAccessNode for recipient
	recipientNodeUUID := getFileAccessNodeUUID(recipientUsername, fileStructUUID)
	recipientInvUUID := getInvStructUUID(recipientUsername, fileStructUUID)
	
	hashedRecipientUsername := userlib.Hash([]byte(recipientUsername))
	
	recipientNode := &FileAccessNode{
		Username:       recipientUsername,
		HashedUsername: hashedRecipientUsername,
		InvStructUUID:  recipientInvUUID,
		ShareeUUIDs:    []uuid.UUID{},
	}
	
	recipientNodeBytes, err := json.Marshal(recipientNode)
	if err != nil {
		return uuid.Nil, err
	}
	
	encryptedRecipientNode, err := encryptThenMAC(recipientNodeBytes, fileEncKey, fileMACKey)
	if err != nil {
		return uuid.Nil, err
	}
	
	userlib.DatastoreSet(recipientNodeUUID, encryptedRecipientNode)
	
	// Update my FileAccessNode to include recipient in sharees
	myNodeBytes, ok := userlib.DatastoreGet(myNodeUUID)
	if !ok {
		return uuid.Nil, errors.New("my access node not found")
	}
	
	decryptedMyNode, err := verifyMACThenDecrypt(myNodeBytes, fileEncKey, fileMACKey)
	if err != nil {
		return uuid.Nil, err
	}
	
	var myNode FileAccessNode
	err = json.Unmarshal(decryptedMyNode, &myNode)
	if err != nil {
		return uuid.Nil, err
	}
	
	// Add recipient to my sharees list
	myNode.ShareeUUIDs = append(myNode.ShareeUUIDs, recipientNodeUUID)
	
	myNodeBytes, err = json.Marshal(myNode)
	if err != nil {
		return uuid.Nil, err
	}
	
	encryptedMyNode, err := encryptThenMAC(myNodeBytes, fileEncKey, fileMACKey)
	if err != nil {
		return uuid.Nil, err
	}
	
	userlib.DatastoreSet(myNodeUUID, encryptedMyNode)
	
	// Create InvStruct for recipient
	recipientInvStruct := &InvStruct{
		FileStructUUID: fileStructUUID,
		FileEncKey:     fileEncKey,
		FileMACKey:     fileMACKey,
		SharerNodeUUID: myNodeUUID,
		SharerUsername: userdata.Username,
	}
	
	// Hybrid encrypt InvStruct for recipient with our signature
	recipientHybridInv, err := hybridEncrypt(recipientInvStruct, recipientPubKey, userdata.SignKey)
	if err != nil {
		return uuid.Nil, err
	}
	
	recipientHybridInvBytes, err := json.Marshal(recipientHybridInv)
	if err != nil {
		return uuid.Nil, err
	}
	
	userlib.DatastoreSet(recipientInvUUID, recipientHybridInvBytes)
	
	// Return the invitation UUID
	return recipientInvUUID, nil
}

// ============================================================================
// ACCEPT INVITATION
// ============================================================================

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Load UserStruct
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	
	hashedFilename := hashFilename(filename)
	
	// Check if filename already exists in user's namespace
	if _, exists := userStruct.Files[hashedFilename]; exists {
		return errors.New("filename already exists in personal namespace")
	}
	
	// Get invitation from datastore
	invBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation not found or has been revoked")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invBytes, &hybridInv)
	if err != nil {
		return err
	}
	
	// Decrypt and verify invitation (decryptInvitation verifies signature)
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return errors.New("failed to decrypt/verify invitation - may be tampered or revoked")
	}
	
	// Verify the invitation claims to be from the expected sender
	if invStruct.SharerUsername != senderUsername {
		return errors.New("invitation not from claimed sender - security violation")
	}
	
	fileStructUUID := invStruct.FileStructUUID
	
	// Try to access the file to verify invitation is valid (not revoked)
	fileStructBytes, ok := userlib.DatastoreGet(fileStructUUID)
	if !ok {
		return errors.New("file no longer exists or invitation has been revoked")
	}
	
	// Try to decrypt with provided keys to ensure they're valid
	_, err = verifyMACThenDecrypt(fileStructBytes, invStruct.FileEncKey, invStruct.FileMACKey)
	if err != nil {
		return errors.New("invitation has been revoked - keys no longer valid")
	}
	
	// Add file to my UserStruct
	userStruct.Files[hashedFilename] = FilePointers{
		FileStructUUID: fileStructUUID,
		InvStructUUID:  invitationPtr,
	}
	
	// Store updated UserStruct
	err = storeUserStruct(userdata.Username, userdata.Password, userStruct)
	if err != nil {
		return err
	}
	
	return nil
}

// ============================================================================
// REVOKE ACCESS
// ============================================================================

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Load UserStruct
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	
	hashedFilename := hashFilename(filename)
	
	// Check if file exists
	filePointers, exists := userStruct.Files[hashedFilename]
	if !exists {
		return errors.New("file not found in personal namespace")
	}
	
	// Get InvStruct to get file keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		return errors.New("invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return err
	}
	
	// Decrypt InvStruct
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return err
	}
	
	oldFileEncKey := invStruct.FileEncKey
	oldFileMACKey := invStruct.FileMACKey
	fileStructUUID := invStruct.FileStructUUID
	
	// Generate NEW file keys
	newFileEncKey, newFileMACKey := deriveFileKeys()
	
	// Get FileStruct
	fileStructBytes, ok := userlib.DatastoreGet(fileStructUUID)
	if !ok {
		return errors.New("file struct not found")
	}
	
	decryptedFileStruct, err := verifyMACThenDecrypt(fileStructBytes, oldFileEncKey, oldFileMACKey)
	if err != nil {
		return err
	}
	
	var fileStruct FileStruct
	err = json.Unmarshal(decryptedFileStruct, &fileStruct)
	if err != nil {
		return err
	}
	
	// Get FileAccess
	fileAccessBytes, ok := userlib.DatastoreGet(fileStruct.AccessUUID)
	if !ok {
		return errors.New("file access not found")
	}
	
	decryptedFileAccess, err := verifyMACThenDecrypt(fileAccessBytes, oldFileEncKey, oldFileMACKey)
	if err != nil {
		return err
	}
	
	var fileAccess FileAccess
	err = json.Unmarshal(decryptedFileAccess, &fileAccess)
	if err != nil {
		return err
	}
	
	// Get owner (my) node
	ownerNodeBytes, ok := userlib.DatastoreGet(fileAccess.OwnerNodeUUID)
	if !ok {
		return errors.New("owner node not found")
	}
	
	decryptedOwnerNode, err := verifyMACThenDecrypt(ownerNodeBytes, oldFileEncKey, oldFileMACKey)
	if err != nil {
		return err
	}
	
	var ownerNode FileAccessNode
	err = json.Unmarshal(decryptedOwnerNode, &ownerNode)
	if err != nil {
		return err
	}
	
	// Find the revoked user's node UUID in my sharees
	revokedNodeUUID := getFileAccessNodeUUID(recipientUsername, fileStructUUID)
	
	// Check if recipient is in my direct sharees
	found := false
	newShareeList := []uuid.UUID{}
	for _, shareeUUID := range ownerNode.ShareeUUIDs {
		if shareeUUID == revokedNodeUUID {
			found = true
			// Don't add to new list (removing them)
		} else {
			newShareeList = append(newShareeList, shareeUUID)
		}
	}
	
	if !found {
		return errors.New("recipient is not a direct sharee")
	}
	
	// Update owner node with new sharee list
	ownerNode.ShareeUUIDs = newShareeList
	
	// Collect all valid user nodes (not revoked)
	validNodes := []FileAccessNode{ownerNode}
	validNodeUUIDs := []uuid.UUID{fileAccess.OwnerNodeUUID}
	
	// BFS to collect all valid nodes (excluding revoked subtree)
	queue := []uuid.UUID{}
	for _, shareeUUID := range ownerNode.ShareeUUIDs {
		queue = append(queue, shareeUUID)
	}
	
	for len(queue) > 0 {
		currentNodeUUID := queue[0]
		queue = queue[1:]
		
		// Get node
		nodeBytes, ok := userlib.DatastoreGet(currentNodeUUID)
		if !ok {
			continue // Skip if not found
		}
		
		decryptedNode, err := verifyMACThenDecrypt(nodeBytes, oldFileEncKey, oldFileMACKey)
		if err != nil {
			continue // Skip if can't decrypt
		}
		
		var node FileAccessNode
		err = json.Unmarshal(decryptedNode, &node)
		if err != nil {
			continue
		}
		
		validNodes = append(validNodes, node)
		validNodeUUIDs = append(validNodeUUIDs, currentNodeUUID)
		
		// Add children to queue
		for _, shareeUUID := range node.ShareeUUIDs {
			queue = append(queue, shareeUUID)
		}
	}
	
	// Re-encrypt all file data structures with new keys
	// 1. Re-encrypt FileStruct
	fileStructBytes, err = json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	encryptedFileStruct, err := encryptThenMAC(fileStructBytes, newFileEncKey, newFileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStructUUID, encryptedFileStruct)
	
	// 2. Re-encrypt FileAccess
	fileAccessBytes, err = json.Marshal(fileAccess)
	if err != nil {
		return err
	}
	encryptedFileAccess, err := encryptThenMAC(fileAccessBytes, newFileEncKey, newFileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStruct.AccessUUID, encryptedFileAccess)
	
	// 3. Re-encrypt FileContent
	fileContentBytes, ok := userlib.DatastoreGet(fileStruct.ContentUUID)
	if !ok {
		return errors.New("file content not found")
	}
	
	decryptedFileContent, err := verifyMACThenDecrypt(fileContentBytes, oldFileEncKey, oldFileMACKey)
	if err != nil {
		return err
	}
	
	var fileContent FileContent
	err = json.Unmarshal(decryptedFileContent, &fileContent)
	if err != nil {
		return err
	}
	
	// Re-encrypt FileContent with new keys
	fileContentBytes, err = json.Marshal(fileContent)
	if err != nil {
		return err
	}
	encryptedFileContent, err := encryptThenMAC(fileContentBytes, newFileEncKey, newFileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStruct.ContentUUID, encryptedFileContent)
	
	// 4. Re-encrypt all chunks
	currentChunkUUID := fileContent.HeadUUID
	for {
		chunkBytes, ok := userlib.DatastoreGet(currentChunkUUID)
		if !ok {
			break
		}
		
		var chunk FileChunkContent
		err = json.Unmarshal(chunkBytes, &chunk)
		if err != nil {
			break
		}
		
		// Decrypt chunk content with old keys
		decryptedChunkContent, err := verifyMACThenDecrypt(chunk.EncryptedContent, oldFileEncKey, oldFileMACKey)
		if err != nil {
			break
		}
		
		// Re-encrypt with new keys
		reEncryptedContent, err := encryptThenMAC(decryptedChunkContent, newFileEncKey, newFileMACKey)
		if err != nil {
			break
		}
		
		chunk.EncryptedContent = reEncryptedContent
		
		// Store re-encrypted chunk
		chunkBytes, err = json.Marshal(chunk)
		if err != nil {
			break
		}
		userlib.DatastoreSet(currentChunkUUID, chunkBytes)
		
		// Move to next chunk
		if chunk.NextUUID == nil {
			break
		}
		currentChunkUUID = *chunk.NextUUID
	}
	
	// 5. Re-encrypt all valid FileAccessNodes and create new InvStructs
	for i, node := range validNodes {
		nodeUUID := validNodeUUIDs[i]
		
		// Re-encrypt node
		nodeBytes, err := json.Marshal(node)
		if err != nil {
			continue
		}
		encryptedNode, err := encryptThenMAC(nodeBytes, newFileEncKey, newFileMACKey)
		if err != nil {
			continue
		}
		userlib.DatastoreSet(nodeUUID, encryptedNode)
		
		// Get username from node
		username := node.Username
		
		// Get user's public key
		userPubKey, ok := userlib.KeystoreGet(username + "_enc")
		if !ok {
			continue // Skip if can't find public key
		}
		
		// Create new InvStruct for this user with new keys
		// Owner is re-sharing, so SharerUsername is the owner
		newInvStruct := &InvStruct{
			FileStructUUID: fileStructUUID,
			FileEncKey:     newFileEncKey,
			FileMACKey:     newFileMACKey,
			SharerNodeUUID: nodeUUID,
			SharerUsername: userdata.Username, // Owner is the sharer after revocation
		}
		
		// Hybrid encrypt new InvStruct with owner's signature
		newHybridInv, err := hybridEncrypt(newInvStruct, userPubKey, userdata.SignKey)
		if err != nil {
			continue
		}
		
		newHybridInvBytes, err := json.Marshal(newHybridInv)
		if err != nil {
			continue
		}
		
		// Overwrite old invitation with new one (same UUID!)
		userlib.DatastoreSet(node.InvStructUUID, newHybridInvBytes)
	}
	
	return nil
}
