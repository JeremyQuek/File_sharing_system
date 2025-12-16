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
// Constants
// ============================================================================

const CHUNK_SIZE = 4096 // 4KB chunks for efficient append

// ============================================================================
// Data Structs
// ============================================================================

// user metadata stored at deterministic UUID (plaintext)
type UserMetadata struct {
	Salt           []byte
	UserStructUUID uuid.UUID
}

// user's encrypted file namespace
type UserStruct struct {
	Files      map[string]FilePointers // hashed filename -> pointers
	PrivEncKey userlib.PKEDecKey       // RSA private key (encrypted in datastore)
	SignKey    userlib.DSSignKey       // DSA signing key (encrypted in datastore)
}

type FilePointers struct {
	FileStructUUID uuid.UUID
	InvStructUUID  uuid.UUID
}

// file structure
type FileStruct struct {
	ContentUUID uuid.UUID
	AccessUUID  uuid.UUID
}

type FileContent struct {
	HeadUUID uuid.UUID
	TailUUID uuid.UUID
}

type FileChunkContent struct {
	EncryptedContent []byte // The actual encrypted data
}

type FileChunkMetadata struct {
	ContentUUID uuid.UUID  // Points to FileChunkContent
	NextUUID    *uuid.UUID // Points to next chunk's metadata (nil if last)
}

// access control tree
type FileAccess struct {
	OwnerNodeUUID uuid.UUID
}

type FileAccessNode struct {
	Username       string     // plaintext username (encrypted with file keys anyway)
	HashedUsername []byte
	InvStructUUID  uuid.UUID
	ShareeUUIDs    []uuid.UUID // list of child nodes
}

// invitation structure
type InvStruct struct {
	FileStructUUID uuid.UUID
	FileEncKey     []byte
	FileMACKey     []byte
	SharerNodeUUID uuid.UUID
	SharerUsername string // Username of person who created this invitation
}

// wrapper for hybrid encryption
type HybridInvStruct struct {
	RSAEncryptedSymKey    []byte
	SymEncryptedInvStruct []byte
	Signature             []byte // Digital signature by sender to prove authenticity
}

// user struct for holding session data
type User struct {
	Username   string
	Password   string
	PrivEncKey userlib.PKEDecKey
	SignKey    userlib.DSSignKey
}

// ============================================================================
// UUID Generation
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
// Key derivation
// ============================================================================

func deriveUserKeys(password string, salt []byte) (encKey, macKey []byte, err error) {
	// generate master key using Argon2
	masterKey := userlib.Argon2Key([]byte(password), salt, 16)
	
	// derive encryption and MAC keys using HKDF, keeps everything client side
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
	// generate random keys for file encryption and MAC
	encKey = userlib.RandomBytes(16)
	macKey = userlib.RandomBytes(16)
	return encKey, macKey
}

// ============================================================================
// Encryption/decryption
// ============================================================================

func encryptThenMAC(data, encKey, macKey []byte) ([]byte, error) {
	// encrypt data
	iv := userlib.RandomBytes(16)
	encrypted := userlib.SymEnc(encKey, iv, data)
	
	// MAC next
	mac, err := userlib.HMACEval(macKey, encrypted)
	if err != nil {
		return nil, err
	}
	
	// concatenate: MAC || encrypted data
	result := append(mac, encrypted...)
	return result, nil
}

func verifyMACThenDecrypt(data, encKey, macKey []byte) ([]byte, error) {
	// edge case: check for minimum length
	if len(data) < 64 {
		return nil, errors.New("data too short")
	}
	
	// split MAC and encrypted data
	mac := data[:64]
	encrypted := data[64:]
	
	// verify MAC
	expectedMAC, err := userlib.HMACEval(macKey, encrypted)
	if err != nil {
		return nil, err
	}
	
	if !userlib.HMACEqual(mac, expectedMAC) {
		return nil, errors.New("MAC verification failed")
	}
	
	// decrypt data
	decrypted := userlib.SymDec(encKey, encrypted)
	return decrypted, nil
}

// ============================================================================
// Hybrid encryption for InvStruct
// ============================================================================

func hybridEncrypt(invStruct *InvStruct, recipientPubKey userlib.PKEEncKey, senderSignKey userlib.DSSignKey) (*HybridInvStruct, error) {
	// 1. generate random symmetric key
	symKey := userlib.RandomBytes(16)
	
	// 2. derive enc/mac keys from symmetric key
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
	
	// 3. marshal and encrypt InvStruct
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
	
	// 5. sign the encrypted invitation to prove sender identity
	// sign over both the RSA encrypted key and the symmetric encrypted invitation
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
	// 1. verify signature first to authenticate sender
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
	
	// 3. derive enc/mac keys from symmetric key
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
	
	// 4. verify MAC and decrypt InvStruct
	invBytes, err := verifyMACThenDecrypt(hybridInv.SymEncryptedInvStruct, encKey, macKey)
	if err != nil {
		return nil, err
	}
	
	// 5. unmarshal InvStruct
	var invStruct InvStruct
	err = json.Unmarshal(invBytes, &invStruct)
	if err != nil {
		return nil, err
	}
	
	return &invStruct, nil
}

// helper function to decrypt invitation and automatically get sharer's verify key --> decrypt and then verify signature
func decryptInvitation(hybridInv *HybridInvStruct, recipientPrivKey userlib.PKEDecKey) (*InvStruct, error) {
	// decrypt to get the SharerUsername
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
	
	// verify the signature using sharer's verify key
	sharerVerifyKey, ok := userlib.KeystoreGet(invStruct.SharerUsername + "_verify")
	if !ok {
		return nil, errors.New("sharer's verify key not found")
	}
	
	// verify signature
	toVerify := append(hybridInv.RSAEncryptedSymKey, hybridInv.SymEncryptedInvStruct...)
	err = userlib.DSVerify(sharerVerifyKey, toVerify, hybridInv.Signature)
	if err != nil {
		return nil, errors.New("signature verification failed - invitation tampered or not from claimed sharer")
	}
	
	return &invStruct, nil
}

// ============================================================================
// Storage and retrieval
// ============================================================================

func storeUserStruct(username, password string, userStruct *UserStruct) error {
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
	
	// derive keys locally as usual
	encKey, macKey, err := deriveUserKeys(password, userMeta.Salt)
	if err != nil {
		return err
	}
	
	// marshal UserStruct
	userStructBytes, err := json.Marshal(userStruct)
	if err != nil {
		return err
	}
	
	// encrypt and MAC
	encrypted, err := encryptThenMAC(userStructBytes, encKey, macKey)
	if err != nil {
		return err
	}
	
	userlib.DatastoreSet(userMeta.UserStructUUID, encrypted)
	return nil
}

func loadUserStruct(username, password string) (*UserStruct, error) {
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
	
	// derive keys
	encKey, macKey, err := deriveUserKeys(password, userMeta.Salt)
	if err != nil {
		return nil, err
	}
	
	// get encrypted UserStruct
	encryptedData, ok := userlib.DatastoreGet(userMeta.UserStructUUID)
	if !ok {
		return nil, errors.New("user struct not found")
	}
	
	// verify MAC and decrypt
	userStructBytes, err := verifyMACThenDecrypt(encryptedData, encKey, macKey)
	if err != nil {
		return nil, errors.New("authentication failed - wrong password or data tampered")
	}
	
	// unmarshal UserStruct
	var userStruct UserStruct
	err = json.Unmarshal(userStructBytes, &userStruct)
	if err != nil {
		return nil, err
	}
	
	// ensure Files map is not nil (JSON unmarshals empty object as nil)
	if userStruct.Files == nil {
		userStruct.Files = make(map[string]FilePointers)
	}
	
	return &userStruct, nil
}

// ============================================================================
// Initialize user
// ============================================================================

func InitUser(username string, password string) (userdataptr *User, err error) {
	// edge: check for empty username
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	
	// edge: check if user already exists
	userMetaUUID := getUserMetadataUUID(username)
	if _, ok := userlib.DatastoreGet(userMetaUUID); ok {
		return nil, errors.New("user already exists")
	}
	
	// generate RSA and DSA keypairs
	pubEncKey, privEncKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	
	// store public keys in Keystore
	err = userlib.KeystoreSet(username+"_enc", pubEncKey)
	if err != nil {
		return nil, err
	}
	
	err = userlib.KeystoreSet(username+"_verify", verifyKey)
	if err != nil {
		return nil, err
	}
	
	// generate salt
	salt := userlib.RandomBytes(16)
	
	// derive encryption and MAC keys
	encKey, macKey, err := deriveUserKeys(password, salt)
	if err != nil {
		return nil, err
	}
	
	// create UserStruct with private keys
	userStruct := &UserStruct{
		Files:      make(map[string]FilePointers),
		PrivEncKey: privEncKey,
		SignKey:    signKey,
	}
	
	// marshal UserStruct
	userStructBytes, err := json.Marshal(userStruct)
	if err != nil {
		return nil, err
	}
	
	// encrypt UserStruct and then MAC
	encrypted, err := encryptThenMAC(userStructBytes, encKey, macKey)
	if err != nil {
		return nil, err
	}
	
	// store UserStruct
	userStructUUID := getUserStructUUID(username)
	userlib.DatastoreSet(userStructUUID, encrypted)
	
	// create and store UserMetadata
	userMeta := &UserMetadata{
		Salt:           salt,
		UserStructUUID: userStructUUID,
	}
	
	userMetaBytes, err := json.Marshal(userMeta)
	if err != nil {
		return nil, err
	}
	
	userlib.DatastoreSet(userMetaUUID, userMetaBytes)
	
	// create User session object
	userdata := &User{
		Username:   username,
		Password:   password,
		PrivEncKey: privEncKey,
		SignKey:    signKey,
	}
	
	return userdata, nil
}

// ============================================================================
// Get user
// ============================================================================

func GetUser(username string, password string) (userdataptr *User, err error) {
	// edge: check for empty username
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	
	// try to load UserStruct (this verifies password)
	userStruct, err := loadUserStruct(username, password)
	if err != nil {
		return nil, err
	}
	
	// create User session object with private keys from UserStruct --> statelessness
	userdata := &User{
		Username:   username,
		Password:   password,
		PrivEncKey: userStruct.PrivEncKey,
		SignKey:    userStruct.SignKey,
	}
	
	return userdata, nil
}

// ============================================================================
// Store file
// ============================================================================

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	
	hashedFilename := hashFilename(filename)
	
	// check if file already exists
	if _, exists := userStruct.Files[hashedFilename]; exists {
		// file exists - overwrite content
		return userdata.overwriteFile(filename, content, userStruct)
	}
	
	// create new file
	return userdata.createNewFile(filename, content, userStruct)
}

func (userdata *User) createNewFile(filename string, content []byte, userStruct *UserStruct) error {
	// generate file encryption and MAC keys
	fileEncKey, fileMACKey := deriveFileKeys()
	
	// split content into chunks and create linked list
	var headMetaUUID, tailMetaUUID uuid.UUID
	var prevMetaUUID *uuid.UUID = nil
	
	// split content into CHUNK_SIZE pieces
	for i := 0; i < len(content); i += CHUNK_SIZE {
		end := i + CHUNK_SIZE
		if end > len(content) {
			end = len(content)
		}
		chunkContent := content[i:end]
		
		// create UUIDs for content and metadata
		contentUUID := uuid.New()
		metaUUID := uuid.New()
		
		if i == 0 {
			headMetaUUID = metaUUID
		}
		tailMetaUUID = metaUUID
		
		// encrypt and store chunk content
		encryptedContent, err := encryptThenMAC(chunkContent, fileEncKey, fileMACKey)
		if err != nil {
			return err
		}
		
		chunkContentStruct := &FileChunkContent{
			EncryptedContent: encryptedContent,
		}
		
		chunkContentBytes, err := json.Marshal(chunkContentStruct)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(contentUUID, chunkContentBytes)
		
		// create and store chunk metadata
		chunkMeta := &FileChunkMetadata{
			ContentUUID: contentUUID,
			NextUUID:    nil,
		}
		
		chunkMetaBytes, err := json.Marshal(chunkMeta)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(metaUUID, chunkMetaBytes)
		
		// update previous chunk's NextUUID
		if prevMetaUUID != nil {
			prevMetaBytes, ok := userlib.DatastoreGet(*prevMetaUUID)
			if !ok {
				return errors.New("previous chunk metadata not found")
			}
			
			var prevMeta FileChunkMetadata
			err = json.Unmarshal(prevMetaBytes, &prevMeta)
			if err != nil {
				return err
			}
			
			prevMeta.NextUUID = &metaUUID
			prevMetaBytes, err = json.Marshal(prevMeta)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(*prevMetaUUID, prevMetaBytes)
		}
		
		prevMetaUUID = &metaUUID
	}
	
	// edge: empty file --> still make a new file with no content
	if len(content) == 0 {
		contentUUID := uuid.New()
		metaUUID := uuid.New()
		headMetaUUID = metaUUID
		tailMetaUUID = metaUUID
		
		encryptedContent, err := encryptThenMAC([]byte{}, fileEncKey, fileMACKey)
		if err != nil {
			return err
		}
		
		chunkContentStruct := &FileChunkContent{
			EncryptedContent: encryptedContent,
		}
		
		chunkContentBytes, err := json.Marshal(chunkContentStruct)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(contentUUID, chunkContentBytes)
		
		chunkMeta := &FileChunkMetadata{
			ContentUUID: contentUUID,
			NextUUID:    nil,
		}
		
		chunkMetaBytes, err := json.Marshal(chunkMeta)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(metaUUID, chunkMetaBytes)
	}
	
	// create FileContent
	fileContent := &FileContent{
		HeadUUID: headMetaUUID,
		TailUUID: tailMetaUUID,
	}
	
	// store FileContent
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
	
	// create FileAccessNode for owner
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
	
	// create FileAccess
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
	
	// create FileStruct
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
	
	// create InvStruct for owner
	invStruct := &InvStruct{
		FileStructUUID: fileStructUUID,
		FileEncKey:     fileEncKey,
		FileMACKey:     fileMACKey,
		SharerNodeUUID: fileAccessNodeUUID,
		SharerUsername: userdata.Username,
	}
	
	// get owner's public key
	ownerPubKey, ok := userlib.KeystoreGet(userdata.Username + "_enc")
	if !ok {
		return errors.New("owner public key not found")
	}
	
	// hybrid encrypt InvStruct with signature
	hybridInv, err := hybridEncrypt(invStruct, ownerPubKey, userdata.SignKey)
	if err != nil {
		return err
	}
	
	hybridInvBytes, err := json.Marshal(hybridInv)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(invStructUUID, hybridInvBytes)
	
	// update UserStruct
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
	
	// get InvStruct to get keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		return errors.New("invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err := json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return err
	}
	
	// decrypt and verify invitation
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return err
	}
	
	// get file encryption and MAC keys
	fileEncKey := invStruct.FileEncKey
	fileMACKey := invStruct.FileMACKey
	
	// get FileStruct
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
	
	// get FileContent
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
	
	// split content into chunks and create linked list
	var headMetaUUID, tailMetaUUID uuid.UUID
	var prevMetaUUID *uuid.UUID = nil
	
	// split content into CHUNK_SIZE pieces
	for i := 0; i < len(content); i += CHUNK_SIZE {
		end := i + CHUNK_SIZE
		if end > len(content) {
			end = len(content)
		}
		chunkContent := content[i:end]
		
		// create UUIDs for content and metadata
		contentUUID := uuid.New()
		metaUUID := uuid.New()
		
		if i == 0 {
			headMetaUUID = metaUUID
		}
		tailMetaUUID = metaUUID
		
		// encrypt and store chunk content
		encryptedContent, err := encryptThenMAC(chunkContent, fileEncKey, fileMACKey)
		if err != nil {
			return err
		}
		
		chunkContentStruct := &FileChunkContent{
			EncryptedContent: encryptedContent,
		}
		
		chunkContentBytes, err := json.Marshal(chunkContentStruct)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(contentUUID, chunkContentBytes)
		
		// create and store chunk metadata
		chunkMeta := &FileChunkMetadata{
			ContentUUID: contentUUID,
			NextUUID:    nil,
		}
		
		chunkMetaBytes, err := json.Marshal(chunkMeta)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(metaUUID, chunkMetaBytes)
		
		// update previous chunk's NextUUID
		if prevMetaUUID != nil {
			prevMetaBytes, ok := userlib.DatastoreGet(*prevMetaUUID)
			if !ok {
				return errors.New("previous chunk metadata not found")
			}
			
			var prevMeta FileChunkMetadata
			err = json.Unmarshal(prevMetaBytes, &prevMeta)
			if err != nil {
				return err
			}
			
			prevMeta.NextUUID = &metaUUID
			prevMetaBytes, err = json.Marshal(prevMeta)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(*prevMetaUUID, prevMetaBytes)
		}
		
		prevMetaUUID = &metaUUID
	}
	
	// edge: handle empty file case
	if len(content) == 0 {
		contentUUID := uuid.New()
		metaUUID := uuid.New()
		headMetaUUID = metaUUID
		tailMetaUUID = metaUUID
		
		encryptedContent, err := encryptThenMAC([]byte{}, fileEncKey, fileMACKey)
		if err != nil {
			return err
		}
		
		chunkContentStruct := &FileChunkContent{
			EncryptedContent: encryptedContent,
		}
		
		chunkContentBytes, err := json.Marshal(chunkContentStruct)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(contentUUID, chunkContentBytes)
		
		chunkMeta := &FileChunkMetadata{
			ContentUUID: contentUUID,
			NextUUID:    nil,
		}
		
		chunkMetaBytes, err := json.Marshal(chunkMeta)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(metaUUID, chunkMetaBytes)
	}
	
	// update FileContent with new head and tail
	fileContent.HeadUUID = headMetaUUID
	fileContent.TailUUID = tailMetaUUID
	
	// store updated FileContent
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
// Append
// ============================================================================

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// early return for empty append --> we don't need to care about other stuff if there is nothing to append, different from file creation
	if len(content) == 0 {
		return nil
	}
	
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	
	hashedFilename := hashFilename(filename)
	
	// check if file exists
	filePointers, exists := userStruct.Files[hashedFilename]
	if !exists {
		return errors.New("file not found")
	}
	
	// get InvStruct to get keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		return errors.New("invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return err
	}
	
	// decrypt InvStruct
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return err
	}
	
	fileEncKey := invStruct.FileEncKey
	fileMACKey := invStruct.FileMACKey
	
	// get FileStruct
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
	
	// get FileContent
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
	
	// split content into new chunks
	var firstNewMetaUUID uuid.UUID
	var lastNewMetaUUID uuid.UUID
	var prevMetaUUID *uuid.UUID = nil
	
	for i := 0; i < len(content); i += CHUNK_SIZE {
		end := i + CHUNK_SIZE
		if end > len(content) {
			end = len(content)
		}
		chunkContent := content[i:end]
		
		// create UUIDs for content and metadata
		contentUUID := uuid.New()
		metaUUID := uuid.New()
		
		if i == 0 {
			firstNewMetaUUID = metaUUID
		}
		lastNewMetaUUID = metaUUID
		
		// encrypt and store chunk content
		encryptedContent, err := encryptThenMAC(chunkContent, fileEncKey, fileMACKey)
		if err != nil {
			return err
		}
		
		chunkContentStruct := &FileChunkContent{
			EncryptedContent: encryptedContent,
		}
		
		chunkContentBytes, err := json.Marshal(chunkContentStruct)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(contentUUID, chunkContentBytes)
		
		// create and store chunk metadata
		chunkMeta := &FileChunkMetadata{
			ContentUUID: contentUUID,
			NextUUID:    nil,
		}
		
		chunkMetaBytes, err := json.Marshal(chunkMeta)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(metaUUID, chunkMetaBytes)
		
		// link previous chunk metadata to this new one
		if prevMetaUUID != nil {
			prevMetaBytes, ok := userlib.DatastoreGet(*prevMetaUUID)
			if !ok {
				return errors.New("previous chunk metadata not found")
			}
			
			var prevMeta FileChunkMetadata
			err = json.Unmarshal(prevMetaBytes, &prevMeta)
			if err != nil {
				return err
			}
			
			prevMeta.NextUUID = &metaUUID
			prevMetaBytes, err = json.Marshal(prevMeta)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(*prevMetaUUID, prevMetaBytes)
		}
		
		prevMetaUUID = &metaUUID
	}
	
	// update old tail metadata to point to first new chunk
	oldTailMetaBytes, ok := userlib.DatastoreGet(fileContent.TailUUID)
	if !ok {
		return errors.New("tail chunk metadata not found")
	}
	
	var oldTailMeta FileChunkMetadata
	err = json.Unmarshal(oldTailMetaBytes, &oldTailMeta)
	if err != nil {
		return err
	}
	
	oldTailMeta.NextUUID = &firstNewMetaUUID
	oldTailMetaBytes, err = json.Marshal(oldTailMeta)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileContent.TailUUID, oldTailMetaBytes)
	
	// update FileContent tail pointer to last new chunk
	fileContent.TailUUID = lastNewMetaUUID
	
	// store updated FileContent
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
// Load file
// ============================================================================

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}
	
	hashedFilename := hashFilename(filename)
	
	// check if file exists
	filePointers, exists := userStruct.Files[hashedFilename]
	if !exists {
		return nil, errors.New("file not found")
	}
	
	// get InvStruct to get keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		// file must hv been revoked --> do lazy update --> since when alice revokes for bob, she cannot enter bob's metadata to edit his file access map)
		delete(userStruct.Files, hashedFilename)
		storeUserStruct(userdata.Username, userdata.Password, userStruct)
		return nil, errors.New("file access revoked or invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return nil, err
	}
	
	// decrypt InvStruct
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		// failed to decrypt --> likely revoked with new keys --> do lazy update
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
	
	// get fileContent
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
	
	// traverse linked list of chunks and concatenate content
	var fullContent []byte
	currentMetaUUID := fileContent.HeadUUID
	
	for {
		metaBytes, ok := userlib.DatastoreGet(currentMetaUUID)
		if !ok {
			return nil, errors.New("chunk metadata not found")
		}
		
		var chunkMeta FileChunkMetadata
		err = json.Unmarshal(metaBytes, &chunkMeta)
		if err != nil {
			return nil, err
		}
		
		// get chunk content using ContentUUID from metadata
		contentBytes, ok := userlib.DatastoreGet(chunkMeta.ContentUUID)
		if !ok {
			return nil, errors.New("chunk content not found")
		}
		
		var chunkContent FileChunkContent
		err = json.Unmarshal(contentBytes, &chunkContent)
		if err != nil {
			return nil, err
		}
		
		// decrypt chunk content
		decryptedChunk, err := verifyMACThenDecrypt(chunkContent.EncryptedContent, fileEncKey, fileMACKey)
		if err != nil {
			return nil, err
		}
		
		fullContent = append(fullContent, decryptedChunk...)
		
		if chunkMeta.NextUUID == nil {
			break
		}
		currentMetaUUID = *chunkMeta.NextUUID
	}
	
	return fullContent, nil
}

// ============================================================================
// Create invitation
// ============================================================================

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	
	// edge: check if recipient exists
	recipientPubKey, ok := userlib.KeystoreGet(recipientUsername + "_enc")
	if !ok {
		return uuid.Nil, errors.New("recipient user does not exist")
	}
	
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return uuid.Nil, err
	}
	
	hashedFilename := hashFilename(filename)
	
	// edge: check if file exists
	filePointers, exists := userStruct.Files[hashedFilename]
	if !exists {
		return uuid.Nil, errors.New("file not found in personal namespace")
	}
	
	// get InvStruct to get file keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		return uuid.Nil, errors.New("invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return uuid.Nil, err
	}
	
	// decrypt InvStruct
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return uuid.Nil, err
	}
	
	fileEncKey := invStruct.FileEncKey
	fileMACKey := invStruct.FileMACKey
	fileStructUUID := invStruct.FileStructUUID
	
	// verify I still have valid access by checking if I can decrypt the FileStruct
	fileStructBytes, ok := userlib.DatastoreGet(fileStructUUID)
	if !ok {
		// lazy update vibes
		delete(userStruct.Files, hashedFilename)
		storeUserStruct(userdata.Username, userdata.Password, userStruct)
		return uuid.Nil, errors.New("file no longer exists")
	}
	
	_, err = verifyMACThenDecrypt(fileStructBytes, fileEncKey, fileMACKey)
	if err != nil {
		// lazy update vibes
		delete(userStruct.Files, hashedFilename)
		storeUserStruct(userdata.Username, userdata.Password, userStruct)
		return uuid.Nil, errors.New("access has been revoked - cannot create invitation")
	}
	
	// get my FileAccessNode UUID
	myNodeUUID := getFileAccessNodeUUID(userdata.Username, fileStructUUID)
	
	// create FileAccessNode for recipient --> alice sharing with bob, alice will create for bob
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
	
	// update my FileAccessNode to include recipient in sharees
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
	
	// add recipient to my sharees list
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
	
	// create InvStruct 
	recipientInvStruct := &InvStruct{
		FileStructUUID: fileStructUUID,
		FileEncKey:     fileEncKey,
		FileMACKey:     fileMACKey,
		SharerNodeUUID: myNodeUUID,
		SharerUsername: userdata.Username,
	}
	
	// hybrid encrypt InvStruct for recipient with our signature
	recipientHybridInv, err := hybridEncrypt(recipientInvStruct, recipientPubKey, userdata.SignKey)
	if err != nil {
		return uuid.Nil, err
	}
	
	recipientHybridInvBytes, err := json.Marshal(recipientHybridInv)
	if err != nil {
		return uuid.Nil, err
	}
	
	userlib.DatastoreSet(recipientInvUUID, recipientHybridInvBytes)
	
	return recipientInvUUID, nil
}

// ============================================================================
// Accept invitation
// ============================================================================

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	
	hashedFilename := hashFilename(filename)
	
	// edge: check if filename already exists in user's namespace
	if _, exists := userStruct.Files[hashedFilename]; exists {
		return errors.New("filename already exists in personal namespace")
	}
	
	// get invitation from datastore
	invBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation not found or has been revoked")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invBytes, &hybridInv)
	if err != nil {
		return err
	}
	
	// decrypt and verify invitation
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return errors.New("failed to decrypt/verify invitation - may be tampered or revoked")
	}
	
	// verify origin is same as expected sender
	if invStruct.SharerUsername != senderUsername {
		return errors.New("invitation not from claimed sender - security violation")
	}
	
	fileStructUUID := invStruct.FileStructUUID
	
	// try to access the file to verify invitation is valid (not revoked), and then decrypt
	fileStructBytes, ok := userlib.DatastoreGet(fileStructUUID)
	if !ok {
		return errors.New("file no longer exists or invitation has been revoked")
	}
	
	_, err = verifyMACThenDecrypt(fileStructBytes, invStruct.FileEncKey, invStruct.FileMACKey)
	if err != nil {
		return errors.New("invitation has been revoked - keys no longer valid")
	}
	
	// add file to my UserStruct --> difference from the usual access file
	userStruct.Files[hashedFilename] = FilePointers{
		FileStructUUID: fileStructUUID,
		InvStructUUID:  invitationPtr,
	}
	
	err = storeUserStruct(userdata.Username, userdata.Password, userStruct)
	if err != nil {
		return err
	}
	
	return nil
}

// ============================================================================
// Revoke access
// ============================================================================

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	userStruct, err := loadUserStruct(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	
	hashedFilename := hashFilename(filename)
	
	// edge: check if file exists
	filePointers, exists := userStruct.Files[hashedFilename]
	if !exists {
		return errors.New("file not found in personal namespace")
	}
	
	// get InvStruct to get file keys
	invStructBytes, ok := userlib.DatastoreGet(filePointers.InvStructUUID)
	if !ok {
		return errors.New("invitation not found")
	}
	
	var hybridInv HybridInvStruct
	err = json.Unmarshal(invStructBytes, &hybridInv)
	if err != nil {
		return err
	}
	
	// decrypt InvStruct
	invStruct, err := decryptInvitation(&hybridInv, userdata.PrivEncKey)
	if err != nil {
		return err
	}
	
	oldFileEncKey := invStruct.FileEncKey
	oldFileMACKey := invStruct.FileMACKey
	fileStructUUID := invStruct.FileStructUUID
	
	// G=generate NEW file keys
	newFileEncKey, newFileMACKey := deriveFileKeys()
	
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
	
	// get FileAccess
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
	
	// get owner node
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
	
	// find the revoked user's node UUID in my sharees
	revokedNodeUUID := getFileAccessNodeUUID(recipientUsername, fileStructUUID)
	
	// edge: Check if recipient is in my direct sharees
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
	
	// update owner node with new sharee list
	ownerNode.ShareeUUIDs = newShareeList
	
	// collect all unrevoked user nodes
	validNodes := []FileAccessNode{ownerNode}
	validNodeUUIDs := []uuid.UUID{fileAccess.OwnerNodeUUID}
	
	// BFS to collect all unrevoked nodes
	queue := []uuid.UUID{}
	for _, shareeUUID := range ownerNode.ShareeUUIDs {
		queue = append(queue, shareeUUID)
	}
	
	for len(queue) > 0 {
		currentNodeUUID := queue[0]
		queue = queue[1:]
		
		nodeBytes, ok := userlib.DatastoreGet(currentNodeUUID)
		if !ok {
			continue
		}
		
		decryptedNode, err := verifyMACThenDecrypt(nodeBytes, oldFileEncKey, oldFileMACKey)
		if err != nil {
			continue // Skip if can't decrypt, just escape 
		}
		
		var node FileAccessNode
		err = json.Unmarshal(decryptedNode, &node)
		if err != nil {
			continue
		}
		
		validNodes = append(validNodes, node)
		validNodeUUIDs = append(validNodeUUIDs, currentNodeUUID)
		
		// add children to queue, bfs method
		for _, shareeUUID := range node.ShareeUUIDs {
			queue = append(queue, shareeUUID)
		}
	}
	
	// re-encrypt all file data structures with new keys
	// 1. re-encrypt FileStruct
	fileStructBytes, err = json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	encryptedFileStruct, err := encryptThenMAC(fileStructBytes, newFileEncKey, newFileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStructUUID, encryptedFileStruct)
	
	// 2. re-encrypt FileAccess
	fileAccessBytes, err = json.Marshal(fileAccess)
	if err != nil {
		return err
	}
	encryptedFileAccess, err := encryptThenMAC(fileAccessBytes, newFileEncKey, newFileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStruct.AccessUUID, encryptedFileAccess)
	
	// 3. re-encrypt FileContent
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
	
	// re-encrypt FileContent with new keys
	fileContentBytes, err = json.Marshal(fileContent)
	if err != nil {
		return err
	}
	encryptedFileContent, err := encryptThenMAC(fileContentBytes, newFileEncKey, newFileMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStruct.ContentUUID, encryptedFileContent)
	
	// 4. re-encrypt all chunks (both content and metadata)
	currentMetaUUID := fileContent.HeadUUID
	for {
		// Get metadata
		metaBytes, ok := userlib.DatastoreGet(currentMetaUUID)
		if !ok {
			break
		}
		
		var chunkMeta FileChunkMetadata
		err = json.Unmarshal(metaBytes, &chunkMeta)
		if err != nil {
			break
		}
		
		// Get content
		contentBytes, ok := userlib.DatastoreGet(chunkMeta.ContentUUID)
		if !ok {
			break
		}
		
		var chunkContent FileChunkContent
		err = json.Unmarshal(contentBytes, &chunkContent)
		if err != nil {
			break
		}
		
		// decrypt chunk content with old keys
		decryptedChunkContent, err := verifyMACThenDecrypt(chunkContent.EncryptedContent, oldFileEncKey, oldFileMACKey)
		if err != nil {
			break
		}
		
		// re-encrypt with new keys
		reEncryptedContent, err := encryptThenMAC(decryptedChunkContent, newFileEncKey, newFileMACKey)
		if err != nil {
			break
		}
		
		chunkContent.EncryptedContent = reEncryptedContent
		
		// store re-encrypted content
		contentBytes, err = json.Marshal(chunkContent)
		if err != nil {
			break
		}
		userlib.DatastoreSet(chunkMeta.ContentUUID, contentBytes)

		if chunkMeta.NextUUID == nil {
			break
		}
		currentMetaUUID = *chunkMeta.NextUUID
	}
	
	// 5. re-encrypt all valid FileAccessNodes and create new InvStructs
	for i, node := range validNodes {
		nodeUUID := validNodeUUIDs[i]
		
		nodeBytes, err := json.Marshal(node)
		if err != nil {
			continue
		}
		encryptedNode, err := encryptThenMAC(nodeBytes, newFileEncKey, newFileMACKey)
		if err != nil {
			continue
		}
		userlib.DatastoreSet(nodeUUID, encryptedNode)
		
		username := node.Username
		
		// get user's public key
		userPubKey, ok := userlib.KeystoreGet(username + "_enc")
		if !ok {
			continue 
		}
		
		// create new InvStruct for this user with new keys. owner is re-sharing, so SharerUsername is the owner
		newInvStruct := &InvStruct{
			FileStructUUID: fileStructUUID,
			FileEncKey:     newFileEncKey,
			FileMACKey:     newFileMACKey,
			SharerNodeUUID: nodeUUID,
			SharerUsername: userdata.Username, 
		}
		
		// hybrid encrypt new InvStruct with owner's signature
		newHybridInv, err := hybridEncrypt(newInvStruct, userPubKey, userdata.SignKey)
		if err != nil {
			continue
		}
		
		newHybridInvBytes, err := json.Marshal(newHybridInv)
		if err != nil {
			continue
		}
		
		// overwrite old invitation with new one (same UUID)
		userlib.DatastoreSet(node.InvStructUUID, newHybridInvBytes)
	}
	
	return nil
}
