package client

// package main

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"bytes"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))

	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username    string
	SignKey     userlib.DSSignKey
	UserDecKey1 userlib.PKEDecKey
	UserDecKey2 userlib.PKEDecKey
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileContent struct {
	EncBlock []byte
	NxtBlock *FileContent
}

type File struct {
	Creator           string
	FileLength        int
	FileHead          userlib.UUID
	FileTail          userlib.UUID
	FileContentEncKey []byte
	FileContentMacKey []byte
	AccessListUUID    userlib.UUID
}
type InviteLink struct {
	FileUUID   userlib.UUID
	FileEncKey []byte
	FileMacKey []byte
	UUIDSrc    []byte
}
type Edge struct {
	Sender   string
	Receiver string
	Filename string
}
type AccessList struct {
	Username string
	Filename string
	Edge     []Edge
}

// helper function
func ByteCombine(pBytes ...[]byte) []byte {
	var buffer bytes.Buffer
	for index := 0; index < len(pBytes); index++ {
		buffer.Write(pBytes[index])
	}
	return buffer.Bytes()
}

func EncFile(content []byte, encKey []byte, macKey []byte) (headptr userlib.UUID, tailptr userlib.UUID, err error) {
	now := uuid.New()
	block := 256
	for i := 0; i < len(content); i += block {
		end := i + block
		if end > len(content) {
			end = len(content)
		}
		contentEnc := userlib.SymEnc(encKey, userlib.RandomBytes(16), content[i:end])
		if err != nil {
			return uuid.New(), uuid.New(), err
		}
		nxtSrc := userlib.RandomBytes(16)
		nxt, err := uuid.FromBytes(nxtSrc)
		if err != nil {
			return uuid.New(), uuid.New(), err
		}
		_, ok := userlib.DatastoreGet(nxt)
		for ok {
			nxtSrc := userlib.RandomBytes(16)
			nxt, err := uuid.FromBytes(nxtSrc)
			if err != nil {
				return uuid.New(), uuid.New(), err

			}
			_, ok = userlib.DatastoreGet(nxt)
		}
		contentMac, err := userlib.HMACEval(macKey, ByteCombine(nxtSrc, contentEnc))
		if err != nil {
			return uuid.New(), uuid.New(), err
		}
		userlib.DatastoreSet(now, ByteCombine(contentMac, nxtSrc, contentEnc))
		if i == 0 {
			headptr = now
		}
		if end == len(content) {
			tailptr = now
		}
		now = nxt
	}

	return headptr, tailptr, nil
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// var userdata User
	if username == "" {
		return userdataptr, errors.New(strings.ToTitle("Empty username"))
	}
	userEncKey1, userDecKey1, _ := userlib.PKEKeyGen()
	userEncKey2, userDecKey2, _ := userlib.PKEKeyGen()
	userSignKey, userVerifyKey, _ := userlib.DSKeyGen()
	usernameByte := userlib.Argon2Key([]byte(username), []byte(""), 16)
	userUUID, err := uuid.FromBytes(usernameByte)
	if err != nil {
		return nil, err
	}
	_, ok := userlib.KeystoreGet(username + "1")
	if ok {
		return nil, errors.New(strings.ToTitle("Username Exist"))
	}
	userlib.KeystoreSet(username+"1", userEncKey1)
	userlib.KeystoreSet(username+"2", userEncKey2)
	userlib.KeystoreSet(username+"3", userVerifyKey)
	user := &User{
		Username:    username,
		SignKey:     userSignKey,
		UserDecKey1: userDecKey1,
		UserDecKey2: userDecKey2,
	}
	userByte, err := json.Marshal(user)
	if err != nil {
		return nil, err

	}
	userEncSK := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userEnc := userlib.SymEnc(userEncSK, userlib.RandomBytes(16), userByte)
	userMacKey, err := userlib.HashKDF(userEncSK, []byte("regenerate"))
	if err != nil {
		return nil, err

	}
	userMac, err := userlib.HMACEval(userMacKey[:16], userEnc)
	if err != nil {
		return nil, err

	}
	// fmt.Println(userEncSK, userMacKey)
	// fmt.Println(userEnc, userMac)
	// fmt.Println(len(userMac), len(userEnc), len(ByteCombine(userMac, userEnc)))

	userlib.DatastoreSet(userUUID, ByteCombine(userMac, userEnc))
	// userdata.Username = username
	return user, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	// cal uuid, mac
	usernameByte := userlib.Argon2Key([]byte(username), []byte(""), 16)
	userUUID, err := uuid.FromBytes(usernameByte)
	if err != nil {
		return nil, err
	}
	userEncSK := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userMacKey, err := userlib.HashKDF(userEncSK, []byte("regenerate"))
	if err != nil {
		return nil, err
	}

	// get data
	val, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("User not found"))
	}
	userMac_, userEnc_ := val[:64], val[64:]
	// verify mac
	userMac, err := userlib.HMACEval(userMacKey[:16], userEnc_)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(userMac, userMac_) {
		return nil, errors.New(strings.ToTitle("Wrong password"))
		// what if the data is tampered????
	}
	// decrypt data
	userByte := userlib.SymDec(userEncSK, userEnc_)
	err = json.Unmarshal(userByte, &userdata)
	if err != nil {
		return nil, err
	}

	userdataptr = &userdata
	return userdataptr, nil
}

func MarshObject(FileUUID userlib.UUID, FileToByte []byte, FileEncKey []byte, FileMacKey []byte) error {

	FileToByteEnc := userlib.SymEnc(FileEncKey, userlib.RandomBytes(16), FileToByte)
	FileToByteMac, err := userlib.HMACEval(FileMacKey, FileToByteEnc)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(FileUUID, ByteCombine(FileToByteMac, FileToByteEnc))
	return nil
}

func LongPKEEnc(key userlib.PKEEncKey, text []byte) (ret []byte, err error) {
	for i := 0; i < len(text); i += 64 {
		end := i + 64
		if end > len(text) {
			end = len(text)
		}
		enc, err := userlib.PKEEnc(key, text[i:end])
		if err != nil {
			return nil, err
		}
		ret = ByteCombine(ret, enc)
	}
	return ret, nil
}
func LongPKEDec(key userlib.PKEDecKey, text []byte) (ret []byte, err error) {
	for i := 0; i < len(text); i += 256 {
		end := i + 256
		if end > len(text) {
			end = len(text)
		}
		dec, err := userlib.PKEDec(key, text[i:end])
		if err != nil {
			return nil, err
		}
		ret = ByteCombine(ret, dec)
	}
	return ret, nil
}
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, _ := uuid.FromBytes(userlib.Hash([]byte(filename + "-" + userdata.Username))[:16])
	// what if filename+userdata.username is the same?
	_, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		FileEncKey := userlib.RandomBytes(16)
		FileMacKey := userlib.RandomBytes(16)
		UUIDSrc := userlib.RandomBytes(16)
		FileUUID, _ := uuid.FromBytes(UUIDSrc)
		for _, ok := userlib.DatastoreGet(FileUUID); ok; _, ok = userlib.DatastoreGet(FileUUID) {
			UUIDSrc = userlib.RandomBytes(16)
			FileUUID, _ = uuid.FromBytes(UUIDSrc)
		}
		UserEncKey2, ok := userlib.KeystoreGet(userdata.Username + "2")
		if !ok {
			return errors.New(strings.ToTitle("User info not found"))
		}

		FileUUIDEnc, err := userlib.PKEEnc(UserEncKey2, ByteCombine(FileEncKey, FileMacKey, UUIDSrc))
		if err != nil {
			return err
		}

		tmp := strings.Repeat(userdata.Username+"-", 16)
		srcKey, err := userlib.HashKDF([]byte(tmp[:16]), []byte("Mac FileUUID"))
		if err != nil {
			return err
		}

		FileUUIDMac, err := userlib.HMACEval(srcKey[:16], FileUUIDEnc)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(storageKey, ByteCombine(FileUUIDMac, FileUUIDEnc))

		fileContentEncKey, err := userlib.HashKDF(FileEncKey, []byte("encrypt file content"))
		if err != nil {
			return err
		}
		fileContentMacKey, err := userlib.HashKDF(FileMacKey, []byte("mac file content"))
		if err != nil {
			return err
		}
		fileContentEncKey = fileContentEncKey[:16]
		fileContentMacKey = fileContentMacKey[:16]
		fileHead, fileTail, err := EncFile(content, fileContentEncKey, fileContentMacKey)
		if err != nil {
			return err
		}
		accessListUUID := uuid.New()
		accessList := AccessList{
			Username: userdata.Username,
			Filename: filename,
			Edge:     []Edge{}, //?????
		}
		accessListToByte, err := json.Marshal(accessList)
		if err != nil {
			return err
		}
		accessListEnc := userlib.SymEnc(fileContentEncKey, userlib.RandomBytes(16), accessListToByte)
		accessListMac, err := userlib.HMACEval(fileContentMacKey, accessListEnc)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(accessListUUID, ByteCombine(accessListMac, accessListEnc))

		file := &File{
			Creator:           userdata.Username,
			FileLength:        len(content),
			FileHead:          fileHead,
			FileTail:          fileTail,
			FileContentEncKey: fileContentEncKey,
			FileContentMacKey: fileContentMacKey,
			AccessListUUID:    accessListUUID,
		}
		FileToByte, err := json.Marshal(file)
		if err != nil {
			return err
		}
		err = MarshObject(FileUUID, FileToByte, FileEncKey, FileMacKey)
		if err != nil {
			return err
		}
	} else {
		file, FileUUID, FileEncKey, FileMacKey, _, err := getPointer(filename, userdata)
		if err != nil {
			return err
		}
		file.FileLength = len(content)
		file.FileHead, file.FileTail, err = EncFile(content, file.FileContentEncKey, file.FileContentMacKey)
		if err != nil {
			return err
		}
		FileToByte, err := json.Marshal(&file)
		if err != nil {
			return err
		}
		err = MarshObject(FileUUID, FileToByte, FileEncKey, FileMacKey)
		if err != nil {
			return err
		}
	}

	// }

	return
}
func appendOperator(content []byte, encKey []byte, macKey []byte, tail userlib.UUID) (newTail userlib.UUID, err error) {
	block := 256
	beginBlock, _ := userlib.DatastoreGet(tail)
	contentMac_, nxtSrc, contentEnc := beginBlock[:64], beginBlock[64:80], beginBlock[80:]
	contentMac, err := userlib.HMACEval(macKey, beginBlock[64:])
	if err != nil {
		return newTail, err
	}
	if !userlib.HMACEqual(contentMac, contentMac_) {
		return uuid.New(), errors.New(strings.ToTitle("Filecontent tampered"))
	}
	contentDec := userlib.SymDec(encKey, contentEnc)
	content = ByteCombine(contentDec, content)

	now := tail
	for i := 0; i < len(content); i += block {
		end := i + block
		if end > len(content) {
			end = len(content)
		}
		contentEnc := userlib.SymEnc(encKey, userlib.RandomBytes(16), content[i:end])

		nxt, err := uuid.FromBytes(nxtSrc)
		if err != nil {
			return uuid.New(), err

		}
		_, ok := userlib.DatastoreGet(nxt)
		for ok {
			nxtSrc = userlib.RandomBytes(16)
			nxt, err = uuid.FromBytes(nxtSrc)
			if err != nil {
				return uuid.New(), err
			}
			_, ok = userlib.DatastoreGet(nxt)
		}
		contentMac, err := userlib.HMACEval(macKey, ByteCombine(nxtSrc, contentEnc))
		if err != nil {
			return uuid.New(), err

		}
		userlib.DatastoreSet(now, ByteCombine(contentMac, nxtSrc, contentEnc))

		if end == len(content) {
			newTail = now
		}
		now = nxt
	}

	return newTail, nil
}
func getPointer(filename string, userdata *User) (file File, UUID userlib.UUID, key1 []byte, key2 []byte, src []byte, err error) {
	storageKey, _ := uuid.FromBytes(userlib.Hash([]byte(filename + "-" + userdata.Username))[:16])
	fileUUID, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return file, uuid.New(), nil, nil, nil, errors.New(strings.ToTitle("User does not have this file"))
		// what if attacker delete the fileUUID information
	}

	tmp := strings.Repeat(userdata.Username+"-", 16)
	srcKey, err := userlib.HashKDF([]byte(tmp[:16]), []byte("Mac FileUUID"))
	if err != nil {
		return file, uuid.New(), nil, nil, nil, err
	}

	fileUUIDMac, err := userlib.HMACEval(srcKey[:16], fileUUID[64:])
	if err != nil {
		return file, uuid.New(), nil, nil, nil, err
	}
	if !userlib.HMACEqual(fileUUIDMac, fileUUID[:64]) {
		return file, uuid.New(), nil, nil, nil, errors.New(strings.ToTitle("FileUUID is tampered"))
	}
	fileUUIDec, err := userlib.PKEDec(userdata.UserDecKey2, fileUUID[64:])
	if err != nil {
		return file, uuid.New(), nil, nil, nil, err
	}
	FileEncKey, FileMacKey, UUIDSrc := fileUUIDec[:16], fileUUIDec[16:32], fileUUIDec[32:]
	fileUUIDval, _ := uuid.FromBytes(UUIDSrc)
	FileToByteAll, ok := userlib.DatastoreGet(fileUUIDval)
	if !ok {
		return file, uuid.New(), nil, nil, nil, errors.New(strings.ToTitle("Didn't get file information/ You don't have access to this file"))
		// what if attacker delete the fileUUID information
	}
	FileToByteMac_, FileToByteEnc := FileToByteAll[:64], FileToByteAll[64:]
	FileToByteMac, err := userlib.HMACEval(FileMacKey, FileToByteEnc)
	if err != nil {
		return file, uuid.New(), nil, nil, nil, err
	}
	if !userlib.HMACEqual(FileToByteMac, FileToByteMac_) {
		return file, uuid.New(), nil, nil, nil, errors.New(strings.ToTitle("File information is tampered"))
	}
	FileToByte := userlib.SymDec(FileEncKey, FileToByteEnc)
	err = json.Unmarshal(FileToByte, &file)
	if err != nil {
		return file, uuid.New(), nil, nil, nil, err
	}
	_, err = GetAccessList(file)
	if err != nil {
		return file, uuid.New(), nil, nil, nil, err
	}

	return file, fileUUIDval, FileEncKey, FileMacKey, UUIDSrc, nil
}
func (userdata *User) AppendToFile(filename string, content []byte) error {
	file, fileUUID, FileEncKey, FileMacKey, _, err := getPointer(filename, userdata)
	if err != nil {
		return err
	}
	tailptr := file.FileTail
	newTail, _ := appendOperator(content, file.FileContentEncKey, file.FileContentMacKey, tailptr)
	file.FileTail = newTail
	file.FileLength += len(content)
	FileToByte, err := json.Marshal(file)
	if err != nil {
		return err
	}
	err = MarshObject(fileUUID, FileToByte, FileEncKey, FileMacKey)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	file, _, _, _, _, err := getPointer(filename, userdata)
	if err != nil {
		return nil, err

	}
	now := file.FileHead
	for val, ok := userlib.DatastoreGet(now); ok; val, ok = userlib.DatastoreGet(now) {

		contentMac_, nxtSrc, contentEnc := val[:64], val[64:80], val[80:]
		contentMac, err := userlib.HMACEval(file.FileContentMacKey, val[64:])
		if err != nil {
			return nil, err

		}
		if !userlib.HMACEqual(contentMac, contentMac_) {
			return nil, errors.New(strings.ToTitle("Filecontent tampered"))
		}
		contentDec := userlib.SymDec(file.FileContentEncKey, contentEnc)
		content = ByteCombine(content, contentDec)
		now, err = uuid.FromBytes(nxtSrc)
		if err != nil {
			return nil, err
		}
	}
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	_, fileUUID, fileEncKey, fileMacKey, src, err := getPointer(filename, userdata)
	if err != nil {
		return invitationPtr, err
	}
	inviteLink := &InviteLink{
		FileUUID:   fileUUID,
		FileEncKey: fileEncKey,
		FileMacKey: fileMacKey,
		UUIDSrc:    src,
	}
	inviteLinkUUID, _ := uuid.FromBytes(userlib.Hash([]byte(filename + "-" + userdata.Username + "-" + recipientUsername))[:16])
	inviteLinkContentToByte, _ := json.Marshal(inviteLink)
	encKey, _ := userlib.KeystoreGet(recipientUsername + "1")
	inviteLinkContentToByteEnc, err := LongPKEEnc(encKey, inviteLinkContentToByte)
	if err != nil {
		return uuid.New(), err
	}
	sig, err := userlib.DSSign(userdata.SignKey, inviteLinkContentToByteEnc)
	if err != nil {
		return uuid.New(), err
	}
	userlib.DatastoreSet(inviteLinkUUID, ByteCombine(sig, inviteLinkContentToByteEnc))
	return inviteLinkUUID, nil
}
func GetAccessList(file File) (accessList AccessList, err error) {
	accessListAll, _ := userlib.DatastoreGet(file.AccessListUUID)
	accessListMac, accessListEnc := accessListAll[:64], accessListAll[64:]
	accessListMac_, err := userlib.HMACEval(file.FileContentMacKey, accessListEnc)
	if err != nil {
		return accessList, err
	}
	if !userlib.HMACEqual(accessListMac, accessListMac_) {
		return accessList, errors.New(strings.ToTitle("AccessList is tampered"))
	}
	accessListToByte := userlib.SymDec(file.FileContentEncKey, accessListEnc)
	err = json.Unmarshal(accessListToByte, &accessList)
	if err != nil {
		return accessList, err
	}
	return accessList, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	storageKey, _ := uuid.FromBytes(userlib.Hash([]byte(filename + "-" + userdata.Username))[:16])
	_, ok := userlib.DatastoreGet(storageKey)
	if ok {
		return errors.New(strings.ToTitle("User has this file"))
	}
	inviteLinkAll, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("Invitelink is revoked"))
	}
	verifyKey, _ := userlib.KeystoreGet(senderUsername + "3")
	err := userlib.DSVerify(verifyKey, inviteLinkAll[256:], inviteLinkAll[:256])
	if err != nil {
		return err
	}
	inviteLinkContentToByte, err := LongPKEDec(userdata.UserDecKey1, inviteLinkAll[256:])
	if err != nil {
		return err
	}
	var inviteLink InviteLink
	err = json.Unmarshal(inviteLinkContentToByte, &inviteLink)
	if err != nil {
		return err
	}
	FileToByteAll, ok := userlib.DatastoreGet(inviteLink.FileUUID)
	if !ok {
		return errors.New(strings.ToTitle("Didn't get file information"))
		// what if attacker delete the fileUUID information
	}

	// get file accessList
	FileToByteMac_, FileToByteEnc := FileToByteAll[:64], FileToByteAll[64:]
	FileToByteMac, err := userlib.HMACEval(inviteLink.FileMacKey, FileToByteEnc)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(FileToByteMac, FileToByteMac_) {
		return errors.New(strings.ToTitle("File information is tampered"))
	}
	FileToByte := userlib.SymDec(inviteLink.FileEncKey, FileToByteEnc)
	var file File
	err = json.Unmarshal(FileToByte, &file)
	if err != nil {
		return err
	}
	// update accessList
	accessList, err := GetAccessList(file)
	if err != nil {
		return err
	}

	edge := Edge{
		Sender:   senderUsername,
		Receiver: userdata.Username,
		Filename: filename,
	}
	accessList.Edge = append(accessList.Edge, edge)
	accessListToByte, err := json.Marshal(accessList)
	if err != nil {
		return err
	}
	err = MarshObject(file.AccessListUUID, accessListToByte, file.FileContentEncKey, file.FileContentMacKey)
	if err != nil {
		return err
	}

	// store file info for user
	UserEncKey2, ok := userlib.KeystoreGet(userdata.Username + "2")
	if !ok {
		return errors.New(strings.ToTitle("User info not found"))
	}
	FileUUIDEnc, err := userlib.PKEEnc(UserEncKey2, ByteCombine(inviteLink.FileEncKey, inviteLink.FileMacKey, inviteLink.UUIDSrc))
	if err != nil {
		return err
	}
	tmp := strings.Repeat(userdata.Username+"-", 16)
	srcKey, err := userlib.HashKDF([]byte(tmp[:16]), []byte("Mac FileUUID"))
	if err != nil {
		return err
	}
	FileUUIDMac, err := userlib.HMACEval(srcKey[:16], FileUUIDEnc)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, ByteCombine(FileUUIDMac, FileUUIDEnc))

	return nil
}

func DeleteAccess(list *AccessList, recipientUsername string) (ok bool) {
	queue := []string{}
	len1 := len(list.Edge)
	for i := 0; i < len(list.Edge); i++ {
		if list.Edge[i].Receiver == recipientUsername {
			queue = append(queue, list.Edge[i].Receiver)
			storageKey, _ := uuid.FromBytes(userlib.Hash([]byte(list.Edge[i].Filename + "-" + list.Edge[i].Receiver))[:16])
			userlib.DatastoreDelete(storageKey)
			list.Edge = append(list.Edge[:i], list.Edge[i+1:]...)

			i -= 1
		}
	}
	for len(queue) > 0 {
		senderName := queue[0]
		queue = queue[1:]
		for i := 0; i < len(list.Edge); i++ {
			if list.Edge[i].Sender == senderName {
				queue = append(queue, list.Edge[i].Receiver)
				storageKey, _ := uuid.FromBytes(userlib.Hash([]byte(list.Edge[i].Filename + "-" + list.Edge[i].Receiver))[:16])
				userlib.DatastoreDelete(storageKey)
				list.Edge = append(list.Edge[:i], list.Edge[i+1:]...)

				i -= 1

			}
		}
	}
	len2 := len(list.Edge)
	// println("delete done")
	return len1 != len2
}

func UpdateInfo(node *AccessList, FileEncKey []byte, FileMacKey []byte, UUIDSrc []byte) error {
	storageKey, _ := uuid.FromBytes(userlib.Hash([]byte(node.Filename + "-" + node.Username))[:16])
	UserEncKey2, ok := userlib.KeystoreGet(node.Username + "2")
	// println(len(node.Edge), node.Username)
	if !ok {
		return errors.New(strings.ToTitle("User info not found"))
	}
	FileUUIDEnc, err := userlib.PKEEnc(UserEncKey2, ByteCombine(FileEncKey, FileMacKey, UUIDSrc))
	if err != nil {
		return err
	}
	tmp := strings.Repeat(node.Username+"-", 16)
	println("update info begin")

	srcKey, err := userlib.HashKDF([]byte(tmp[:16]), []byte("Mac FileUUID"))
	if err != nil {
		return err
	}
	FileUUIDMac, err := userlib.HMACEval(srcKey[:16], FileUUIDEnc)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, ByteCombine(FileUUIDMac, FileUUIDEnc))

	for i := 0; i < len(node.Edge); i++ {
		// println(i)
		storageKey, _ := uuid.FromBytes(userlib.Hash([]byte(node.Edge[i].Filename + "-" + node.Edge[i].Receiver))[:16])
		UserEncKey2, ok := userlib.KeystoreGet(node.Edge[i].Receiver + "2")
		if !ok {
			return errors.New(strings.ToTitle("User info not found"))
		}
		FileUUIDEnc, err := userlib.PKEEnc(UserEncKey2, ByteCombine(FileEncKey, FileMacKey, UUIDSrc))
		if err != nil {
			return err
		}

		tmp := strings.Repeat(node.Edge[i].Receiver+"-", 16)

		srcKey, err := userlib.HashKDF([]byte(tmp[:16]), []byte("Mac FileUUID"))
		if err != nil {
			return err
		}
		FileUUIDMac, err := userlib.HMACEval(srcKey[:16], FileUUIDEnc)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(storageKey, ByteCombine(FileUUIDMac, FileUUIDEnc))
	}
	// println("update done")
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	file, oldFileUUID, _, _, _, err := getPointer(filename, userdata)
	if err != nil {
		return err

	}
	accessList, err := GetAccessList(file)

	if err != nil {
		return err
	}
	// firstUser, firstName := accessList.Username, accessList.Filename
	ok := DeleteAccess(&accessList, recipientUsername)
	if !ok {
		inviteLinkUUID, _ := uuid.FromBytes(userlib.Hash([]byte(filename + "-" + userdata.Username + "-" + recipientUsername))[:16])
		userlib.DatastoreDelete(inviteLinkUUID)
		return nil
	}
	// new enc FileUUID
	// storageKey, _ := uuid.FromBytes(userlib.Hash([]byte(firstName + firstUser))[:16])
	FileEncKey := userlib.RandomBytes(16)
	FileMacKey := userlib.RandomBytes(16)
	UUIDSrc := userlib.RandomBytes(16)
	FileUUID, _ := uuid.FromBytes(UUIDSrc)
	for _, ok := userlib.DatastoreGet(FileUUID); ok; _, ok = userlib.DatastoreGet(FileUUID) {
		UUIDSrc = userlib.RandomBytes(16)
		FileUUID, _ = uuid.FromBytes(UUIDSrc)
	}

	// userlib.DatastoreSet(storageKey, ByteCombine(FileUUIDMac, FileUUIDEnc))
	// new filecontent and its pointer
	fileContentEncKey, err := userlib.HashKDF(FileEncKey, []byte("encrypt file content"))
	if err != nil {
		return err
	}
	fileContentMacKey, err := userlib.HashKDF(FileMacKey, []byte("mac file content"))
	if err != nil {
		return err
	}
	fileContentEncKey = fileContentEncKey[:16]
	fileContentMacKey = fileContentMacKey[:16]

	var oldContent []byte
	now := file.FileHead
	for val, ok := userlib.DatastoreGet(now); ok; val, ok = userlib.DatastoreGet(now) {

		contentMac_, nxtSrc, contentEnc := val[:64], val[64:80], val[80:]
		contentMac, err := userlib.HMACEval(file.FileContentMacKey, val[64:])
		if err != nil {
			return err

		}
		if !userlib.HMACEqual(contentMac, contentMac_) {
			return (errors.New(strings.ToTitle("Filecontent tampered")))
		}
		contentDec := userlib.SymDec(file.FileContentEncKey, contentEnc)
		oldContent = ByteCombine(oldContent, contentDec)
		userlib.DatastoreDelete(now)
		now, err = uuid.FromBytes(nxtSrc)
		if err != nil {
			return err
		}
	}
	file.FileHead, file.FileTail, err = EncFile(oldContent, fileContentEncKey, fileContentMacKey)
	if err != nil {
		return err

	}
	// new accessList with its pointer
	accessListToByte, err := json.Marshal(accessList)
	if err != nil {
		return err
	}
	accessListUUID := uuid.New()
	MarshObject(accessListUUID, accessListToByte, fileContentEncKey, fileContentMacKey)
	// new file information
	file.AccessListUUID = accessListUUID
	file.FileContentEncKey = fileContentEncKey
	file.FileContentMacKey = fileContentMacKey

	userlib.DatastoreDelete(oldFileUUID)
	FileToByte, err := json.Marshal(file)
	if err != nil {
		return err
	}
	MarshObject(FileUUID, FileToByte, FileEncKey, FileMacKey)
	// update information for user still have access
	UpdateInfo(&accessList, FileEncKey, FileMacKey, UUIDSrc)

	return nil
}

func main() {
	// someUsefulThings()
	fmt.Println("hello")
	// InitUser("alice", "123456")
	// InitUser("bob", "")
	// InitUser("talice", "ilove")
	// aliceLaptop, err := GetUser("alice", "123456")

	// if err != nil {
	// 	panic(err)
	// }
	// // key1, _, _ := userlib.PKEKeyGen()
	// // a1 := LongPKEEnc(key1, []byte("asdgsdgdsbc"))
	// // a2 := LongPKEEnc(key1, []byte("opbrsvrredq"))
	// // fmt.Println(len(a1))
	// // fmt.Println(len(a2))

	// alicePhone, err := GetUser("alice", "123456")
	// if err != nil {
	// 	panic(err)
	// }
	// err = aliceLaptop.StoreFile("abc.txt", []byte(" This is beginning "))
	// if err != nil {
	// 	panic(err)
	// }
	// claraPhone, err := GetUser("talice", "ilove")
	// if err != nil {
	// 	panic(err)
	// }
	// err = claraPhone.StoreFile("abc.tx", []byte("this is end"))
	// if err != nil {
	// 	panic(err)
	// }
	// content, err := alicePhone.LoadFile("abc.txt")
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(string(content))
	defaultPassword := "password"
	aliceFile := "aliceFile.txt"
	const contentOne = "Bitcoin is Nick's favorite "
	const contentTwo = "digital "
	const contentThree = "cryptocurrency!"

	// bobFile := "bobFile.txt"
	// charlesFile := "charlesFile.txt"

	alice, err := InitUser("alice", defaultPassword)
	if err != nil {
		panic(err)
	}
	bob, err := InitUser("bob", defaultPassword)
	if err != nil {
		panic(err)
	}
	err = alice.StoreFile(aliceFile, []byte(contentOne))
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("give and revoke bob's access")
	invite, err := alice.CreateInvitation(aliceFile, "bob")
	if err != nil {
		panic(err)
	}
	err = bob.AcceptInvitation("alice", invite, aliceFile)
	if err != nil {
		panic(err)
	}
	read, err := bob.LoadFile(aliceFile)
	if err != nil {
		panic(err)
	}
	println(string(read))
	err = bob.StoreFile(aliceFile, []byte(contentTwo))
	if err != nil {
		panic(err)
	}
	err = alice.RevokeAccess(aliceFile, "bob")
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Now bob try to make malicious store")
	err = bob.StoreFile(aliceFile, []byte(contentThree))
	if err != nil {
		panic(err)
	}
	read, err = alice.LoadFile(aliceFile)
	if err != nil {
		panic(err)
	}
	println(string(read))

}
