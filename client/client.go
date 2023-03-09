package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being usC:\doc\outpack\final_designdoc.mded. It can be
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

type Share_list struct {
	Owner_list map[string]int
	// Owner_list["alice"] = 1
}

type User struct {
	Username     string
	Privatekey   userlib.PKEDecKey //ras dec_key
	Signaturekey userlib.DSSignKey //sign_key
	Filesalt     []byte            //randombytes
	Sharesalt    []byte

	Filelist     map[string]uuid.UUID //filename: file_struct_uuid
	Keylist      map[string][]byte    // filename : symkey
	Filehmaclist map[string][]byte    // not used
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type file struct {
	Flag      int    // root file or not
	Content   []byte // seed of content / invitation_seed
	Last_byte []byte // seed of last byte
	Owner     string //owner name
}

type share struct {
	Fuuid     uuid.UUID         //
	Fsyskey   []byte            //
	Secretkey userlib.PKEDecKey //senderuser privatekey
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//id of user_password : password _ set
	// set = cipher + hmac
	//id of user_struct : userstruct _ set

	var userdata User
	if username == "" {
		err = fmt.Errorf("username cant be empty")
		return nil, err //error
	}
	idofuser, _ := uuid.FromBytes(userlib.Hash([]byte(username + "signin"))[:16])
	//var retmsg bool
	_, flag := userlib.DatastoreGet(idofuser)
	if flag {
		err = fmt.Errorf("username exsited")
		return nil, err //error
	} else {
		userdata.Username = username
		userdata.Filelist = make(map[string]uuid.UUID)
		userdata.Keylist = make(map[string][]byte)
		userdata.Filehmaclist = make(map[string][]byte)
		userdata.Filesalt = userlib.RandomBytes(20)
		userdata.Sharesalt = userlib.RandomBytes(20)

		var rsa_publickey, rsa_privatekey, _ = userlib.PKEKeyGen() //rsa
		var signaturekey, sig_verifykey, _ = userlib.DSKeyGen()    // sign
		//fmt.Println(username + "privatekey")
		//fmt.Println(rsa_privatekey)
		//fmt.Println(username)

		userdata.Privatekey = rsa_privatekey
		userdata.Signaturekey = signaturekey

		err := userlib.KeystoreSet(username+"publickey", rsa_publickey)
		if err != nil {
			return nil, err
		}
		err = userlib.KeystoreSet(username+"verifykey", sig_verifykey)
		if err != nil {
			return nil, err
		}

		signinkey, _ := userlib.HashKDF(userlib.Hash([]byte(username + "signin"))[:16], []byte("signin"))
		signinhmac_key, _ := userlib.HashKDF(userlib.Hash([]byte(username + "signin"))[:16], []byte("signin_hmac"))

		loginkey, _ := userlib.HashKDF(userlib.Hash([]byte(username + "login"))[:16], []byte("login"))
		loginhmac_key, _ := userlib.HashKDF(userlib.Hash([]byte(username + "login"))[:16], []byte("login_hmac"))

		//hashofuser := userlib.Hash([]byte(username + password))
		//idofuserstruct, _ := uuid.FromBytes(hashofuser[:16])

		userstruct, _ := json.Marshal(userdata)

		password_cipher := userlib.SymEnc(signinkey[:16],
			userlib.RandomBytes(16),
			[]byte(password))
		userstruct_cipher := userlib.SymEnc(loginkey[:16],
			userlib.RandomBytes(16),
			userstruct)

		password_hmac, _ := userlib.HMACEval(signinhmac_key[:16], password_cipher)
		userstruct_hmac, _ := userlib.HMACEval(loginhmac_key[:16], userstruct_cipher)

		idofuserstruct, _ := uuid.FromBytes(userlib.Hash([]byte(username + "login"))[:16])

		userlib.DatastoreSet(idofuser, []byte(string(password_cipher)+string(password_hmac)))
		userlib.DatastoreSet(idofuserstruct, []byte(string(userstruct_cipher)+string(userstruct_hmac)))
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	idofuser, _ := uuid.FromBytes(userlib.Hash([]byte(username + "signin"))[:16])
	password_set, flag := userlib.DatastoreGet(idofuser)
	if !flag {
		err = fmt.Errorf("username not existed / ds has been modified")
		return nil, err
	}

	//password_set, _ := userlib.DatastoreGet(idofuser)
	password_cipher := password_set[:len(password_set)-64]
	password_hmac := password_set[len(password_set)-64:]

	signinkey, _ := userlib.HashKDF(userlib.Hash([]byte(username + "signin"))[:16], []byte("signin"))
	signinhmac_key, _ := userlib.HashKDF(userlib.Hash([]byte(username + "signin"))[:16], []byte("signin_hmac"))

	expected_password_hmac, _ := userlib.HMACEval(signinhmac_key[:16], password_cipher)

	switch {
	case !userlib.HMACEqual(password_hmac, expected_password_hmac):
		err = fmt.Errorf("datastore(password) has been modified")
		return nil, err
	default:
		password_plain := userlib.SymDec(signinkey[:16], password_cipher)
		if string(password_plain) != password {
			err = fmt.Errorf("password error")
			return nil, err
		}
	}

	idofuserstruct, _ := uuid.FromBytes(userlib.Hash([]byte(username + "login"))[:16])
	userstruct_set, _ := userlib.DatastoreGet(idofuserstruct)
	userstruct_cipher := userstruct_set[:len(userstruct_set)-64]
	userstruct_hmac := userstruct_set[len(userstruct_set)-64:]

	loginkey, _ := userlib.HashKDF(userlib.Hash([]byte(username + "login"))[:16], []byte("login"))
	loginhmac_key, _ := userlib.HashKDF(userlib.Hash([]byte(username + "login"))[:16], []byte("login_hmac"))

	expected_userstruct_hmac, _ := userlib.HMACEval(loginhmac_key[:16], userstruct_cipher)

	switch {
	case !userlib.HMACEqual(userstruct_hmac, expected_userstruct_hmac):
		err = fmt.Errorf("datastore(userstruct) has been modified")
		return nil, err
	default:
		userstruct_plain := userlib.SymDec(loginkey[:16], userstruct_cipher)
		err := json.Unmarshal(userstruct_plain, &userdata)
		if err != nil {
			return nil, err
		}
		userdataptr = &userdata
		return userdataptr, nil
		//fmt.Println(userdata)
	}
}

func (userdata *User) UserLoad() (userdataptr *User, err error) {
	username := userdata.Username
	//fmt.Println(username)
	var userstruct User
	idofuserstruct, _ := uuid.FromBytes(userlib.Hash([]byte(username + "login"))[:16])
	userstruct_set, flag := userlib.DatastoreGet(idofuserstruct)
	if !flag {
		err = fmt.Errorf("ds error")
		return nil, err
	}
	userstruct_cipher := userstruct_set[:len(userstruct_set)-64]
	userstruct_hmac := userstruct_set[len(userstruct_set)-64:]

	loginkey, _ := userlib.HashKDF(userlib.Hash([]byte(username + "login"))[:16], []byte("login"))
	loginhmac_key, _ := userlib.HashKDF(userlib.Hash([]byte(username + "login"))[:16], []byte("login_hmac"))

	expected_userstruct_hmac, _ := userlib.HMACEval(loginhmac_key[:16], userstruct_cipher)

	switch {
	case !userlib.HMACEqual(userstruct_hmac, expected_userstruct_hmac):
		err = fmt.Errorf("datastore(userstruct) has been modified")
		return nil, err
	default:
		userstruct_plain := userlib.SymDec(loginkey[:16], userstruct_cipher)
		err := json.Unmarshal(userstruct_plain, &userstruct)
		if err != nil {
			return nil, err
		}
		//fmt.Println(&userstruct.Filelist)
		//fmt.Println(userdata.Filelist)

		userdataptr = &userstruct

		//fmt.Println(userdata.Filelist)
		//fmt.Println(userstruct)
		return userdataptr, nil
	}
}

func (userdata *User) UserUpdate() (err error) {
	//fmt.Println(userdata.Filelist)
	username := userdata.Username

	loginkey, _ := userlib.HashKDF(userlib.Hash([]byte(username + "login"))[:16], []byte("login"))
	loginhmac_key, _ := userlib.HashKDF(userlib.Hash([]byte(username + "login"))[:16], []byte("login_hmac"))

	//hashofuser := userlib.Hash([]byte(username + password))
	//idofuserstruct, _ := uuid.FromBytes(hashofuser[:16])

	userstruct, _ := json.Marshal(userdata)

	userstruct_cipher := userlib.SymEnc(loginkey[:16],
		userlib.RandomBytes(16),
		userstruct)

	userstruct_hmac, _ := userlib.HMACEval(loginhmac_key[:16], userstruct_cipher)

	idofuserstruct, _ := uuid.FromBytes(userlib.Hash([]byte(username + "login"))[:16])

	userlib.DatastoreSet(idofuserstruct, []byte(string(userstruct_cipher)+string(userstruct_hmac)))

	//fmt.Println(userdata.Filelist)

	return nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var shareflag bool
	userdata, err = userdata.UserLoad()
	if err != nil {
		return err
	}
	//fmt.Println(userdata.Filelist)
	if fuuid, flag := userdata.Filelist[filename]; flag {
		filestruct_set, flag := userlib.DatastoreGet(fuuid)
		if !flag {
			err = fmt.Errorf("datastore has been modified")
			return err
		}

		filestruct_cipher := filestruct_set[:len(filestruct_set)-64]
		filestruct_hmac := filestruct_set[len(filestruct_set)-64:]

		hmac_key, _ := userlib.HashKDF(userdata.Keylist[filename][:16],
			[]byte(fuuid.String()))
		filehmac, _ := userlib.HMACEval(hmac_key[:16], filestruct_cipher)

		switch {
		case !userlib.HMACEqual(filehmac, filestruct_hmac):
			err = fmt.Errorf("file has been modified")
			return err
		default:
			filestruct_plaintext := userlib.SymDec(userdata.Keylist[filename][:16], filestruct_cipher)
			filestruct := new(file)
			json.Unmarshal(filestruct_plaintext, filestruct)

			tmp_share := new(share)
			tmp_share.Fuuid = userdata.Filelist[filename]
			tmp_share.Fsyskey = userdata.Keylist[filename]
			privatekey := userdata.Privatekey

			var invitation uuid.UUID
			var signature []byte
			//var connect_file_hmac_uuid uuid.UUID
			var sharestruct_cipher_uuid uuid.UUID

			if filestruct.Flag == 0 {
				shareflag = true
			}

			for filestruct.Flag != 0 {
				invitation, _ = uuid.FromBytes(filestruct.Content[:16])
				signature, flag = userlib.DatastoreGet(invitation)
				if !flag {
					err = fmt.Errorf("datastore has been modified")
					return err
				}

				share_seed_uuid, _ := uuid.FromBytes([]byte((invitation.String() +
					string(signature)))[:16])
				//sharestruct_seed_cipher, flag := userlib.DatastoreGet(share_seed_uuid)
				//if !flag {
				//	err = fmt.Errorf("ds has been modified")
				//	return err
				//}

				sharestruct_seed_set, flag := userlib.DatastoreGet(share_seed_uuid)
				if !flag {
					err = fmt.Errorf("ds has been modified / revoke")
					return err
				}
				sharestruct_seed_cipher := sharestruct_seed_set[:len(sharestruct_seed_set)-256]
				sharestruct_seed_sig := sharestruct_seed_set[len(sharestruct_seed_set)-256:]

				verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
				if !flag {
					err = fmt.Errorf("get verifykey error")
					return err
				}

				err = userlib.DSVerify(verify_key,
					sharestruct_seed_cipher,
					sharestruct_seed_sig) //signature check
				if err != nil {
					fmt.Println("sig2 error")
					return err
				}

				sharestruct_seed, err := userlib.PKEDec(privatekey, sharestruct_seed_cipher)
				if err != nil {
					return err
				}
				sharestruct_symkey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_sym_enc"))
				//sharestruct_hmackey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_hmac"))

				sharestruct_cipher_uuid, _ = uuid.FromBytes(sharestruct_seed[:16])
				sharestruct_cipher, flag := userlib.DatastoreGet(sharestruct_cipher_uuid)
				if !flag {
					err = fmt.Errorf("datastore has been modified2")
					return err
				}
				//verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
				//if !flag {
				//	err = fmt.Errorf("get verifykey error")
				//	return err
				//}
				err = userlib.DSVerify(verify_key,
					sharestruct_cipher,
					signature) //signature check
				if err != nil {
					fmt.Println("what the fuck1")
					return err
				}

				sharestruct_plaintext := userlib.SymDec(sharestruct_symkey[:16], sharestruct_cipher)
				//sharestruct_cipher_uuid, _ = uuid.FromBytes([]byte((invitation.String() +
				//	string(signature))[:16]))
				//sharestruct_cipher, flag := userlib.DatastoreGet(sharestruct_cipher_uuid)
				//if !flag {
				//	err = fmt.Errorf("datastore has been modified")
				//	return err
				//}
				//verify_key, _ := userlib.KeystoreGet(filestruct.Owner + "verifykey")
				//err = userlib.DSVerify(verify_key,
				//	sharestruct_cipher,
				//	signature) //signature check
				//if err != nil {
				//	return err
				//}
				//sharestruct_plaintext, err := userlib.PKEDec(privatekey, sharestruct_cipher)
				//if err != nil {
				//	return err
				//}
				err = json.Unmarshal(sharestruct_plaintext, tmp_share)
				if err != nil {
					return err
				}

				connect_file_set, flag := userlib.DatastoreGet(tmp_share.Fuuid)
				if !flag {
					err = fmt.Errorf("datastore has been modified")
					return err
				}
				connect_file_cipher := connect_file_set[:len(connect_file_set)-64]
				connect_file_hmac := connect_file_set[len(connect_file_set)-64:]

				hmac_key, err = userlib.HashKDF(tmp_share.Fsyskey[:16],
					[]byte(tmp_share.Fuuid.String()))
				cur_connect_file_hmac, err := userlib.HMACEval(hmac_key[:16], connect_file_cipher)

				switch {
				case err != nil: //useless
					return err
				case !userlib.HMACEqual(cur_connect_file_hmac, connect_file_hmac): //check connect_file_hmac
					err = fmt.Errorf("file has been modifed")
					return err
				default: //decrypt
					json.Unmarshal(userlib.SymDec(tmp_share.Fsyskey[:16], connect_file_cipher), filestruct)
					privatekey = tmp_share.Secretkey
				}
			}

			var seedofcontent []byte
			var seedoflastbyte []byte

			//if shareflag {
			seedofcontent = userlib.RandomBytes(20)
			seedoflastbyte = userlib.RandomBytes(20)

			filestruct.Content = seedofcontent
			filestruct.Last_byte = seedoflastbyte
			//} else {
			//	seedofcontent = userlib.RandomBytes(20)
			//	seedoflastbyte = userlib.RandomBytes(20)
			//
			//	seedofcontent = filestruct.Content
			//	seedoflastbyte = filestruct.Last_byte
			//}

			uuidofcontent, _ := uuid.FromBytes(seedofcontent[:16])
			contentkey, _ := userlib.HashKDF(seedofcontent[:16], []byte("sym_content"+string(seedofcontent)))

			uuidoflastbyte, _ := uuid.FromBytes(seedoflastbyte[:16])
			lastbytekey, _ := userlib.HashKDF(seedoflastbyte[:16], []byte("sym_lastbyte"+string(seedoflastbyte)))

			hmac_key_content, _ := userlib.HashKDF(seedofcontent[:16], []byte("hmac_content"+string(seedofcontent)))
			hmac_key_lastbyte, _ := userlib.HashKDF(seedoflastbyte[:16], []byte("hmac_lastbyte"+string(seedoflastbyte)))

			cipher_content := userlib.SymEnc(contentkey[:16], userlib.RandomBytes(16), content)
			cipher_lastbyte := userlib.SymEnc(lastbytekey[:16], userlib.RandomBytes(16), []byte(""))

			hmac_content, _ := userlib.HMACEval(hmac_key_content[:16], cipher_content)
			hmac_lastbyte, _ := userlib.HMACEval(hmac_key_lastbyte[:16], cipher_lastbyte)

			//fmt.Println(hmac_key_lastbyte[:10])
			//fmt.Println(lastbytekey[:10])

			userlib.DatastoreSet(uuidofcontent, []byte(string(cipher_content)+
				string(hmac_content)))
			userlib.DatastoreSet(uuidoflastbyte, []byte(string(cipher_lastbyte)+
				string(hmac_lastbyte)))

			new_file, _ := json.Marshal(filestruct)
			//fmt.Println(string(new_file))
			new_file_cipher := userlib.SymEnc(tmp_share.Fsyskey[:16],
				userlib.RandomBytes(16),
				new_file,
			)
			new_file_hmac, _ := userlib.HMACEval(hmac_key[:16], new_file_cipher)

			if shareflag {
				userdata.Filehmaclist[filename] = new_file_hmac
			}

			//userlib.DatastoreDelete(sharestruct_cipher_uuid)
			userlib.DatastoreSet(tmp_share.Fuuid, []byte(string(new_file_cipher)+string(new_file_hmac)))
			//userlib.DatastoreSet(connect_file_hmac_uuid, new_file_hmac)
		}
		//filestruct.Content = content
		//file, _ := json.Marshal(filestruct)
		//tmp_share.file_hmac, _ = userlib.HMACEval(hmac_key, file)

		err := userdata.UserUpdate()
		if err != nil {
			return err
		}

		return nil
	} else {
		filestruct := new(file)
		filestruct.Flag = 0
		filestruct.Owner = userdata.Username
		//filestruct.Content = content
		//if len(content) == 0 {
		//	filestruct.Content = content
		//	filestruct.Last_byte = content
		//} else {
		//	filestruct.Content = content[:len(content)-1]
		//	filestruct.Last_byte = content[len(content)-1:]
		//}

		userdata.Filelist[filename] = uuid.New()
		//uuid.FromBytes([]byte(userdata.Username + filename +
		//string(userdata.Filesalt))[:16])
		userdata.Keylist[filename] = userlib.RandomBytes(20)
		hmac_key, _ := userlib.HashKDF(userdata.Keylist[filename][:16],
			[]byte(userdata.Filelist[filename].String()))

		seedofcontent := userlib.RandomBytes(20)
		seedoflastbyte := userlib.RandomBytes(20)
		filestruct.Content = seedofcontent
		filestruct.Last_byte = seedoflastbyte

		uuidofcontent, _ := uuid.FromBytes(seedofcontent[:16])
		contentkey, _ := userlib.HashKDF(seedofcontent[:16], []byte("sym_content"+string(seedofcontent)))

		uuidoflastbyte, _ := uuid.FromBytes(seedoflastbyte[:16])
		lastbytekey, _ := userlib.HashKDF(seedoflastbyte[:16], []byte("sym_lastbyte"+string(seedoflastbyte)))

		hmac_key_content, _ := userlib.HashKDF(seedofcontent[:16], []byte("hmac_content"+string(seedofcontent)))
		hmac_key_lastbyte, _ := userlib.HashKDF(seedoflastbyte[:16], []byte("hmac_lastbyte"+string(seedoflastbyte)))

		cipher_content := userlib.SymEnc(contentkey[:16], userlib.RandomBytes(16), content)
		cipher_lastbyte := userlib.SymEnc(lastbytekey[:16], userlib.RandomBytes(16), []byte(""))

		hmac_content, _ := userlib.HMACEval(hmac_key_content[:16], cipher_content)
		hmac_lastbyte, _ := userlib.HMACEval(hmac_key_lastbyte[:16], cipher_lastbyte)

		//fmt.Println(hmac_key_lastbyte[:10])
		//fmt.Println(lastbytekey[:10])

		userlib.DatastoreSet(uuidofcontent, []byte(string(cipher_content)+
			string(hmac_content)))
		userlib.DatastoreSet(uuidoflastbyte, []byte(string(cipher_lastbyte)+
			string(hmac_lastbyte)))

		new_file, _ := json.Marshal(filestruct)
		//fmt.Println(string(new_file))
		new_file_cipher := userlib.SymEnc(userdata.Keylist[filename][:16],
			userlib.RandomBytes(16),
			new_file,
		)
		new_file_hmac, _ := userlib.HMACEval(hmac_key[:16], new_file_cipher)
		userdata.Filehmaclist[filename] = new_file_hmac
		//userlib.DatastoreDelete(sharestruct_cipher_uuid)
		userlib.DatastoreSet(userdata.Filelist[filename], []byte(string(new_file_cipher)+string(new_file_hmac)))
		//userlib.DatastoreSet(connect_file_hmac_uuid, new_file_hmac)

		err := userdata.UserUpdate()
		if err != nil {
			return err
		}

		return nil
	}
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var err error
	var shareflag bool
	userdata, err = userdata.UserLoad()
	if err != nil {
		return err
	}

	if fuuid, flag := userdata.Filelist[filename]; flag {
		filestruct_set, flag := userlib.DatastoreGet(fuuid)
		if !flag {
			err = fmt.Errorf("datastore has been modified")
			return err
		}
		filestruct_cipher := filestruct_set[:len(filestruct_set)-64]
		filestruct_hmac := filestruct_set[len(filestruct_set)-64:]

		hmac_key, _ := userlib.HashKDF(userdata.Keylist[filename][:16],
			[]byte(fuuid.String()))
		filehmac, _ := userlib.HMACEval(hmac_key[:16], filestruct_cipher)

		switch {
		case !userlib.HMACEqual(filehmac, filestruct_hmac):
			err = fmt.Errorf("file has been modified1")
			return err
		default:
			filestruct_plaintext := userlib.SymDec(userdata.Keylist[filename][:16], filestruct_cipher)
			filestruct := new(file)
			json.Unmarshal(filestruct_plaintext, filestruct)

			tmp_share := new(share)
			tmp_share.Fuuid = userdata.Filelist[filename]
			tmp_share.Fsyskey = userdata.Keylist[filename]
			privatekey := userdata.Privatekey

			var invitation uuid.UUID
			var signature []byte
			//var connect_file_hmac_uuid uuid.UUID
			var sharestruct_cipher_uuid uuid.UUID

			if filestruct.Flag == 0 {
				shareflag = true
			}

			for filestruct.Flag != 0 {
				invitation, _ = uuid.FromBytes(filestruct.Content[:16])
				signature, flag = userlib.DatastoreGet(invitation)
				if !flag {
					err = fmt.Errorf("datastore has been modified")
					return err
				}

				//connect_file_hmac_uuid, _ = uuid.FromBytes([]byte((invitation.String() +
				//	string(signature))[:16]))
				//connect_file_hmac, flag := userlib.DatastoreGet(connect_file_hmac_uuid)
				//if !flag {
				//	err = fmt.Errorf("datastore has been modified")
				//	return err
				//}

				share_seed_uuid, _ := uuid.FromBytes([]byte((invitation.String() +
					string(signature)))[:16])
				//sharestruct_seed_cipher, flag := userlib.DatastoreGet(share_seed_uuid)
				//if !flag {
				//	err = fmt.Errorf("ds has been modified1")
				//	return err
				//}

				sharestruct_seed_set, flag := userlib.DatastoreGet(share_seed_uuid)
				if !flag {
					err = fmt.Errorf("ds has been modified / revoke")
					return err
				}
				sharestruct_seed_cipher := sharestruct_seed_set[:len(sharestruct_seed_set)-256]
				sharestruct_seed_sig := sharestruct_seed_set[len(sharestruct_seed_set)-256:]

				verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
				if !flag {
					err = fmt.Errorf("get verifykey error")
					return err
				}

				err = userlib.DSVerify(verify_key,
					sharestruct_seed_cipher,
					sharestruct_seed_sig) //signature check
				if err != nil {
					fmt.Println("sig2 error")
					return err
				}

				sharestruct_seed, err := userlib.PKEDec(privatekey, sharestruct_seed_cipher)
				if err != nil {
					return err
				}
				sharestruct_symkey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_sym_enc"))
				//sharestruct_hmackey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_hmac"))

				sharestruct_cipher_uuid, _ = uuid.FromBytes(sharestruct_seed[:16])
				sharestruct_cipher, flag := userlib.DatastoreGet(sharestruct_cipher_uuid)
				if !flag {
					err = fmt.Errorf("datastore has been modified2")
					return err
				}
				//verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
				//if !flag {
				//	err = fmt.Errorf("get verifykey error")
				//	return err
				//}
				err = userlib.DSVerify(verify_key,
					sharestruct_cipher,
					signature) //signature check
				if err != nil {
					fmt.Println("what the fuck1")
					return err
				}

				sharestruct_plaintext := userlib.SymDec(sharestruct_symkey[:16], sharestruct_cipher)
				err = json.Unmarshal(sharestruct_plaintext, tmp_share)
				if err != nil {
					return err
				}

				connect_file_set, flag := userlib.DatastoreGet(tmp_share.Fuuid)
				if !flag {
					err = fmt.Errorf("datastore has been modified")
					return err
				}
				connect_file_cipher := connect_file_set[:len(connect_file_set)-64]
				connect_file_hmac := connect_file_set[len(connect_file_set)-64:]

				hmac_key, err = userlib.HashKDF(tmp_share.Fsyskey[:16],
					[]byte(tmp_share.Fuuid.String()))
				cur_connect_file_hmac, err := userlib.HMACEval(hmac_key[:16], connect_file_cipher)

				switch {
				case err != nil: //signature check
					return err
				case !userlib.HMACEqual(cur_connect_file_hmac, connect_file_hmac): //check connect_file_hmac
					err = fmt.Errorf("file has been modifed")
					return err
				default: //decrypt
					json.Unmarshal(userlib.SymDec(tmp_share.Fsyskey[:16], connect_file_cipher), filestruct)
					privatekey = tmp_share.Secretkey
				}
			}
			//uuidofcontent, _ := uuid.FromBytes(seedofcontent[:16])
			//contentkey, _ := userlib.HashKDF(seedofcontent[:16], []byte("sym_content"+string(seedofcontent)))
			//
			//uuidoflastbyte, _ := uuid.FromBytes(seedoflastbyte[:16])
			//lastbytekey, _ := userlib.HashKDF(seedoflastbyte[:16], []byte("sym_lastbyte"+string(seedoflastbyte)))
			//
			//hmac_key_content, _ := userlib.HashKDF(seedofcontent[:16], []byte("hmac_content"+string(seedofcontent)))
			//hmac_key_lastbyte, _ := userlib.HashKDF(seedoflastbyte[:16], []byte("hmac_lastbyte"+string(seedoflastbyte)))
			//
			//lastbytekey, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("lastbyte"))
			//hmac_key_lastbyte, _ := userlib.HashKDF(hmac_key[:16], []byte("lastbyte"))

			hmac_key_lastbyte, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("hmac_lastbyte"+string(filestruct.Last_byte)))
			lastbytekey, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("sym_lastbyte"+string(filestruct.Last_byte)))
			//fmt.Println(hmac_key_lastbyte[:10])
			//fmt.Println(lastbytekey[:10])

			uidoflastbyte_cipher, _ := uuid.FromBytes(filestruct.Last_byte[:16])
			lastbyte_cipher, _ := userlib.DatastoreGet(uidoflastbyte_cipher)

			hmac_lastbyte := lastbyte_cipher[len(lastbyte_cipher)-64:]
			lastbyte_cipher = lastbyte_cipher[:len(lastbyte_cipher)-64]

			expected_hmac_lastbyte, _ := userlib.HMACEval(hmac_key_lastbyte[:16], lastbyte_cipher)

			var ori_lastbyte []byte

			switch {
			case !userlib.HMACEqual(hmac_lastbyte, expected_hmac_lastbyte):
				err = fmt.Errorf("file has been modified2")
				return err
			default:
				ori_lastbyte = userlib.SymDec(lastbytekey[:16], lastbyte_cipher)
				new_lastbyte := []byte(string(ori_lastbyte) + string(content))

				//uuidofcontent, _ := uuid.FromBytes(seedofcontent[:16])
				//contentkey, _ := userlib.HashKDF(seedofcontent[:16], []byte("sym_content"+string(seedofcontent)))
				//
				//uuidoflastbyte, _ := uuid.FromBytes(seedoflastbyte[:16])
				//lastbytekey, _ := userlib.HashKDF(seedoflastbyte[:16], []byte("sym_lastbyte"+string(seedoflastbyte)))
				//
				//hmac_key_content, _ := userlib.HashKDF(seedofcontent[:16], []byte("hmac_content"+string(seedofcontent)))
				//hmac_key_lastbyte, _ := userlib.HashKDF(seedoflastbyte[:16], []byte("hmac_lastbyte"+string(seedoflastbyte)))
				//
				//hmac_content, _ := userlib.HMACEval(hmac_key_content[:16], content)
				//hmac_lastbyte, _ := userlib.HMACEval(hmac_key_lastbyte[:16], []byte(""))

				//seedoflastbyte := userlib.RandomBytes(20)
				//filestruct.Last_byte = seedoflastbyte

				lastbytekey, _ = userlib.HashKDF(filestruct.Last_byte[:16], []byte("sym_lastbyte"+string(filestruct.Last_byte)))
				hmac_key_lastbyte, _ = userlib.HashKDF(filestruct.Last_byte[:16], []byte("hmac_lastbyte"+string(filestruct.Last_byte)))

				cipher_lastbyte := userlib.SymEnc(lastbytekey[:16], userlib.RandomBytes(16), new_lastbyte)

				hmac_lastbyte, _ = userlib.HMACEval(hmac_key_lastbyte[:16], cipher_lastbyte)
				uidoflastbyte_cipher, _ = uuid.FromBytes(filestruct.Last_byte[:16])

				userlib.DatastoreSet(uidoflastbyte_cipher, []byte(string(cipher_lastbyte)+
					string(hmac_lastbyte)))

				new_file, _ := json.Marshal(filestruct)
				//fmt.Println(string(new_file))
				new_file_cipher := userlib.SymEnc(tmp_share.Fsyskey[:16],
					userlib.RandomBytes(16),
					new_file,
				)
				new_file_hmac, _ := userlib.HMACEval(hmac_key[:16], new_file_cipher)
				if shareflag {
					userdata.Filehmaclist[filename] = new_file_hmac
				}
				//userlib.DatastoreDelete(sharestruct_cipher_uuid)
				userlib.DatastoreSet(tmp_share.Fuuid, []byte(string(new_file_cipher)+string(new_file_hmac)))
				//userlib.DatastoreSet(connect_file_hmac_uuid, new_file_hmac)
			}
			err := userdata.UserUpdate()
			if err != nil {
				return err
			}
			return nil
		}
	} else {
		err = fmt.Errorf("filename error")
		return err
	}
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	shareflag := true
	userdata, err = userdata.UserLoad()
	if err != nil {
		return nil, err
	}
	if fuuid, flag := userdata.Filelist[filename]; flag {
		filestruct_set, flag := userlib.DatastoreGet(fuuid)
		if !flag {
			err = fmt.Errorf("datastore has been modified")
			return nil, err
		}
		filestruct_cipher := filestruct_set[:len(filestruct_set)-64]
		filestruct_hmac := filestruct_set[len(filestruct_set)-64:]

		hmac_key, _ := userlib.HashKDF(userdata.Keylist[filename][:16],
			[]byte(fuuid.String()))
		filehmac, _ := userlib.HMACEval(hmac_key[:16], filestruct_cipher)

		switch {
		case !userlib.HMACEqual(filehmac, filestruct_hmac):
			err = fmt.Errorf("file has been modified1")
			return nil, err
		default:
			filestruct_plaintext := userlib.SymDec(userdata.Keylist[filename][:16], filestruct_cipher)

			//fmt.Println(string(filestruct_plaintext))

			filestruct := new(file)
			err := json.Unmarshal(filestruct_plaintext, filestruct)
			if err != nil {
				return nil, err
			}

			tmp_share := new(share)
			tmp_share.Fuuid = fuuid
			tmp_share.Fsyskey = userdata.Keylist[filename]
			privatekey := userdata.Privatekey

			var invitation uuid.UUID
			var signature []byte
			//var connect_file_hmac_uuid uuid.UUID
			var sharestruct_cipher_uuid uuid.UUID

			if filestruct.Flag != 0 {
				shareflag = false
				for filestruct.Flag != 0 {
					invitation, _ = uuid.FromBytes(filestruct.Content[:16])
					signature, flag = userlib.DatastoreGet(invitation)
					if !flag {
						err = fmt.Errorf("datastore has been modified")
						return nil, err
					}

					share_seed_uuid, _ := uuid.FromBytes([]byte((invitation.String() +
						string(signature)))[:16])
					//sharestruct_seed_cipher, flag := userlib.DatastoreGet(share_seed_uuid)
					//if !flag {
					//	err = fmt.Errorf("ds has been modified")
					//	return nil, err
					//}
					sharestruct_seed_set, flag := userlib.DatastoreGet(share_seed_uuid)
					if !flag {
						err = fmt.Errorf("ds has been modified / revoke")
						return nil, err
					}
					sharestruct_seed_cipher := sharestruct_seed_set[:len(sharestruct_seed_set)-256]
					sharestruct_seed_sig := sharestruct_seed_set[len(sharestruct_seed_set)-256:]

					verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
					if !flag {
						err = fmt.Errorf("get verifykey error")
						return nil, err
					}

					err = userlib.DSVerify(verify_key,
						sharestruct_seed_cipher,
						sharestruct_seed_sig) //signature check
					if err != nil {
						fmt.Println("sig2 error")
						return nil, err
					}

					sharestruct_seed, err := userlib.PKEDec(privatekey, sharestruct_seed_cipher)
					if err != nil {
						return nil, err
					}
					sharestruct_symkey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_sym_enc"))
					//sharestruct_hmackey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_hmac"))

					sharestruct_cipher_uuid, _ = uuid.FromBytes(sharestruct_seed[:16])
					sharestruct_cipher, flag := userlib.DatastoreGet(sharestruct_cipher_uuid)
					if !flag {
						err = fmt.Errorf("datastore has been modified2")
						return nil, err
					}
					//verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
					//if !flag {
					//	err = fmt.Errorf("get verifykey error")
					//	return nil, err
					//}
					err = userlib.DSVerify(verify_key,
						sharestruct_cipher,
						signature) //signature check
					if err != nil {
						fmt.Println("what the fuck1")
						return nil, err
					}

					sharestruct_plaintext := userlib.SymDec(sharestruct_symkey[:16], sharestruct_cipher)
					err = json.Unmarshal(sharestruct_plaintext, tmp_share)
					if err != nil {
						return nil, err
					}

					connect_file_set, flag := userlib.DatastoreGet(tmp_share.Fuuid)
					if !flag {
						err = fmt.Errorf("datastore has been modified")
						return nil, err
					}
					connect_file_cipher := connect_file_set[:len(connect_file_set)-64]
					connect_file_hmac := connect_file_set[len(connect_file_set)-64:]

					hmac_key, err = userlib.HashKDF(tmp_share.Fsyskey[:16],
						[]byte(tmp_share.Fuuid.String()))
					cur_connect_file_hmac, err := userlib.HMACEval(hmac_key[:16], connect_file_cipher)

					switch {
					case err != nil: //signature check
						return nil, err
					case !userlib.HMACEqual(cur_connect_file_hmac, connect_file_hmac): //check connect_file_hmac
						err = fmt.Errorf("file has been modifed")
						return nil, err
					default: //decrypt
						json.Unmarshal(userlib.SymDec(tmp_share.Fsyskey[:16], connect_file_cipher), filestruct)
						privatekey = tmp_share.Secretkey
					}
				}

				contentkey, _ := userlib.HashKDF(filestruct.Content[:16], []byte("sym_content"+string(filestruct.Content)))
				lastbytekey, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("sym_lastbyte"+string(filestruct.Last_byte)))
				hmac_key_content, _ := userlib.HashKDF(filestruct.Content[:16], []byte("hmac_content"+string(filestruct.Content)))
				hmac_key_lastbyte, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("hmac_lastbyte"+string(filestruct.Last_byte)))

				uidofcontent_cipher, _ := uuid.FromBytes(filestruct.Content[:16])
				content_cipher, _ := userlib.DatastoreGet(uidofcontent_cipher)
				uidoflastbyte_cipher, _ := uuid.FromBytes(filestruct.Last_byte[:16])
				lastbyte_cipher, _ := userlib.DatastoreGet(uidoflastbyte_cipher)

				hmac_content := content_cipher[len(content_cipher)-64:]
				hmac_lastbyte := lastbyte_cipher[len(lastbyte_cipher)-64:]
				content_cipher = content_cipher[:len(content_cipher)-64]
				lastbyte_cipher = lastbyte_cipher[:len(lastbyte_cipher)-64]

				expected_hmac_content, _ := userlib.HMACEval(hmac_key_content[:16], content_cipher)
				expected_hmac_lastbyte, _ := userlib.HMACEval(hmac_key_lastbyte[:16], lastbyte_cipher)

				var ori_content []byte
				var ori_lastbyte []byte

				switch {
				case !userlib.HMACEqual(hmac_content, expected_hmac_content):
					err = fmt.Errorf("file has been modified2")
					return nil, err
				case !userlib.HMACEqual(hmac_lastbyte, expected_hmac_lastbyte):
					err = fmt.Errorf("file has been modified3")
					return nil, err
				default:
					ori_content = userlib.SymDec(contentkey[:16], content_cipher)
					ori_lastbyte = userlib.SymDec(lastbytekey[:16], lastbyte_cipher)
					content = []byte(string(ori_content) + string(ori_lastbyte))

					if len(ori_lastbyte) != 0 {
						//new_content := content
						//new_lastbyte := ""

						var seedofcontent []byte
						var seedoflastbyte []byte

						if shareflag {
							seedofcontent = userlib.RandomBytes(20)
							seedoflastbyte = userlib.RandomBytes(20)

							filestruct.Content = seedofcontent
							filestruct.Last_byte = seedoflastbyte
						} else {
							seedofcontent = filestruct.Content
							seedoflastbyte = filestruct.Last_byte
						}

						uuidofcontent, _ := uuid.FromBytes(seedofcontent[:16])
						contentkey, _ = userlib.HashKDF(seedofcontent[:16], []byte("sym_content"+string(seedofcontent)))

						uuidoflastbyte, _ := uuid.FromBytes(seedoflastbyte[:16])
						lastbytekey, _ = userlib.HashKDF(seedoflastbyte[:16], []byte("sym_lastbyte"+string(seedoflastbyte)))

						hmac_key_content, _ = userlib.HashKDF(seedofcontent[:16], []byte("hmac_content"+string(seedofcontent)))
						hmac_key_lastbyte, _ = userlib.HashKDF(seedoflastbyte[:16], []byte("hmac_lastbyte"+string(seedoflastbyte)))

						cipher_content := userlib.SymEnc(contentkey[:16], userlib.RandomBytes(16), content)
						cipher_lastbyte := userlib.SymEnc(lastbytekey[:16], userlib.RandomBytes(16), []byte(""))

						hmac_content, _ = userlib.HMACEval(hmac_key_content[:16], cipher_content)
						hmac_lastbyte, _ = userlib.HMACEval(hmac_key_lastbyte[:16], cipher_lastbyte)

						//fmt.Println(hmac_key_lastbyte[:10])
						//fmt.Println(lastbytekey[:10])

						userlib.DatastoreSet(uuidofcontent, []byte(string(cipher_content)+
							string(hmac_content)))
						userlib.DatastoreSet(uuidoflastbyte, []byte(string(cipher_lastbyte)+
							string(hmac_lastbyte)))

						new_file, _ := json.Marshal(filestruct)
						//fmt.Println(string(new_file))
						new_file_cipher := userlib.SymEnc(tmp_share.Fsyskey[:16],
							userlib.RandomBytes(16),
							new_file,
						)
						new_file_hmac, _ := userlib.HMACEval(hmac_key[:16], new_file_cipher)

						if shareflag {
							userdata.Filehmaclist[filename] = new_file_hmac
						}

						//userlib.DatastoreDelete(sharestruct_cipher_uuid)
						userlib.DatastoreSet(tmp_share.Fuuid, []byte(string(new_file_cipher)+string(new_file_hmac)))
					}
				}

			} else {

				contentkey, _ := userlib.HashKDF(filestruct.Content[:16], []byte("sym_content"+string(filestruct.Content)))
				lastbytekey, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("sym_lastbyte"+string(filestruct.Last_byte)))
				hmac_key_content, _ := userlib.HashKDF(filestruct.Content[:16], []byte("hmac_content"+string(filestruct.Content)))
				hmac_key_lastbyte, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("hmac_lastbyte"+string(filestruct.Last_byte)))

				uidofcontent_cipher, _ := uuid.FromBytes(filestruct.Content[:16])
				content_cipher, _ := userlib.DatastoreGet(uidofcontent_cipher)
				uidoflastbyte_cipher, _ := uuid.FromBytes(filestruct.Last_byte[:16])
				lastbyte_cipher, _ := userlib.DatastoreGet(uidoflastbyte_cipher)

				hmac_content := content_cipher[len(content_cipher)-64:]
				hmac_lastbyte := lastbyte_cipher[len(lastbyte_cipher)-64:]
				content_cipher = content_cipher[:len(content_cipher)-64]
				lastbyte_cipher = lastbyte_cipher[:len(lastbyte_cipher)-64]

				expected_hmac_content, _ := userlib.HMACEval(hmac_key_content[:16], content_cipher)
				expected_hmac_lastbyte, _ := userlib.HMACEval(hmac_key_lastbyte[:16], lastbyte_cipher)

				var ori_content []byte
				var ori_lastbyte []byte

				switch {
				case !userlib.HMACEqual(hmac_lastbyte, expected_hmac_lastbyte):
					err = fmt.Errorf("file has been modified4")
					return nil, err
				case !userlib.HMACEqual(hmac_content, expected_hmac_content):
					err = fmt.Errorf("file has been modified5")
					return nil, err
				default:
					ori_content = userlib.SymDec(contentkey[:16], content_cipher)
					ori_lastbyte = userlib.SymDec(lastbytekey[:16], lastbyte_cipher)
					content = []byte(string(ori_content) + string(ori_lastbyte))

					var seedofcontent []byte
					var seedoflastbyte []byte

					if shareflag {
						seedofcontent = userlib.RandomBytes(20)
						seedoflastbyte = userlib.RandomBytes(20)

						filestruct.Content = seedofcontent
						filestruct.Last_byte = seedoflastbyte
					} else {
						seedofcontent = filestruct.Content
						seedoflastbyte = filestruct.Last_byte
					}

					uuidofcontent, _ := uuid.FromBytes(seedofcontent[:16])
					contentkey, _ = userlib.HashKDF(seedofcontent[:16], []byte("sym_content"+string(seedofcontent)))

					uuidoflastbyte, _ := uuid.FromBytes(seedoflastbyte[:16])
					lastbytekey, _ = userlib.HashKDF(seedoflastbyte[:16], []byte("sym_lastbyte"+string(seedoflastbyte)))

					hmac_key_content, _ = userlib.HashKDF(seedofcontent[:16], []byte("hmac_content"+string(seedofcontent)))
					hmac_key_lastbyte, _ = userlib.HashKDF(seedoflastbyte[:16], []byte("hmac_lastbyte"+string(seedoflastbyte)))

					cipher_content := userlib.SymEnc(contentkey[:16], userlib.RandomBytes(16), content)
					cipher_lastbyte := userlib.SymEnc(lastbytekey[:16], userlib.RandomBytes(16), []byte(""))

					hmac_content, _ = userlib.HMACEval(hmac_key_content[:16], cipher_content)
					hmac_lastbyte, _ = userlib.HMACEval(hmac_key_lastbyte[:16], cipher_lastbyte)

					//fmt.Println(hmac_key_lastbyte[:10])
					//fmt.Println(lastbytekey[:10])

					userlib.DatastoreSet(uuidofcontent, []byte(string(cipher_content)+
						string(hmac_content)))
					userlib.DatastoreSet(uuidoflastbyte, []byte(string(cipher_lastbyte)+
						string(hmac_lastbyte)))

					new_file, _ := json.Marshal(filestruct)
					//fmt.Println(string(new_file))
					new_file_cipher := userlib.SymEnc(tmp_share.Fsyskey[:16],
						userlib.RandomBytes(16),
						new_file,
					)
					new_file_hmac, _ := userlib.HMACEval(hmac_key[:16], new_file_cipher)

					if shareflag {
						userdata.Filehmaclist[filename] = new_file_hmac
					}

					//userlib.DatastoreDelete(sharestruct_cipher_uuid)
					userlib.DatastoreSet(tmp_share.Fuuid, []byte(string(new_file_cipher)+string(new_file_hmac)))
					//if len(ori_lastbyte) > 1 {
					//	new_content := []byte(string(ori_content) + string(ori_lastbyte[:len(ori_lastbyte)-1]))
					//	new_lastbyte := ori_lastbyte[len(ori_lastbyte)-1:]
					//}
				}
			}
		}
		err := userdata.UserUpdate()
		if err != nil {
			return nil, err
		}
		return content, nil
	} else {
		err = fmt.Errorf("filename error")
		return nil, err
	}
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	//shareflag := true
	userdata, err = userdata.UserLoad()
	if err != nil {
		return uuid.Nil, err
	}
	fmt.Println(userdata.Filelist)
	if fuuid, flag := userdata.Filelist[filename]; flag {
		filestruct_set, flag := userlib.DatastoreGet(fuuid)
		if !flag {
			err = fmt.Errorf("datastore has been modified")
			return uuid.Nil, err
		}

		filestruct_cipher := filestruct_set[:len(filestruct_set)-64]
		filestruct_hmac := filestruct_set[len(filestruct_set)-64:]

		hmac_key, _ := userlib.HashKDF(userdata.Keylist[filename][:16],
			[]byte(fuuid.String()))
		filehmac, _ := userlib.HMACEval(hmac_key[:16], filestruct_cipher)

		switch {
		case !userlib.HMACEqual(filehmac, filestruct_hmac):
			err = fmt.Errorf("file has been modified")
			return uuid.Nil, err
		default:
			filestruct_plaintext := userlib.SymDec(userdata.Keylist[filename][:16], filestruct_cipher)

			//fmt.Println(string(filestruct_plaintext))

			filestruct := new(file)
			err := json.Unmarshal(filestruct_plaintext, filestruct)
			if err != nil {
				return uuid.Nil, err
			}

			tmp_share := new(share)
			tmp_share.Fuuid = fuuid
			tmp_share.Fsyskey = userdata.Keylist[filename]
			privatekey := userdata.Privatekey

			var invitation uuid.UUID
			var signature []byte
			var signature2 []byte
			//var connect_file_hmac_uuid uuid.UUID
			var sharestruct_cipher_uuid uuid.UUID

			if filestruct.Owner == recipientUsername {
				err = fmt.Errorf("this user has already owned the file")
				return uuid.Nil, err
			}

			if filestruct.Flag != 0 {
				//shareflag = false
				for filestruct.Flag != 0 {
					invitation, _ = uuid.FromBytes(filestruct.Content[:16])
					signature, flag = userlib.DatastoreGet(invitation)
					if !flag {
						err = fmt.Errorf("datastore has been modified / you cant access to the file")
						return uuid.Nil, err
					}

					share_seed_uuid, _ := uuid.FromBytes([]byte((invitation.String() +
						string(signature)))[:16])
					//sharestruct_seed_cipher, flag := userlib.DatastoreGet(share_seed_uuid)
					//if !flag {
					//	err = fmt.Errorf("ds has been modified")
					//	return uuid.Nil, err
					//}

					sharestruct_seed_set, flag := userlib.DatastoreGet(share_seed_uuid)
					if !flag {
						err = fmt.Errorf("ds has been modified / revoke")
						return uuid.Nil, err
					}
					sharestruct_seed_cipher := sharestruct_seed_set[:len(sharestruct_seed_set)-256]
					sharestruct_seed_sig := sharestruct_seed_set[len(sharestruct_seed_set)-256:]

					verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
					if !flag {
						err = fmt.Errorf("get verifykey error")
						return uuid.Nil, err
					}

					err = userlib.DSVerify(verify_key,
						sharestruct_seed_cipher,
						sharestruct_seed_sig) //signature check
					if err != nil {
						fmt.Println("sig2 error")
						return uuid.Nil, err
					}

					sharestruct_seed, err := userlib.PKEDec(privatekey, sharestruct_seed_cipher)
					if err != nil {
						return uuid.Nil, err
					}
					sharestruct_symkey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_sym_enc"))
					//sharestruct_hmackey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_hmac"))

					sharestruct_cipher_uuid, _ = uuid.FromBytes(sharestruct_seed[:16])
					sharestruct_cipher, flag := userlib.DatastoreGet(sharestruct_cipher_uuid)
					if !flag {
						err = fmt.Errorf("datastore has been modified2")
						return uuid.Nil, err
					}
					//verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
					//if !flag {
					//	err = fmt.Errorf("get verifykey error")
					//	return uuid.Nil, err
					//}
					err = userlib.DSVerify(verify_key,
						sharestruct_cipher,
						signature) //signature check
					if err != nil {
						fmt.Println("what the fuck1")
						return uuid.Nil, err
					}

					sharestruct_plaintext := userlib.SymDec(sharestruct_symkey[:16], sharestruct_cipher)
					err = json.Unmarshal(sharestruct_plaintext, tmp_share)
					if err != nil {
						return uuid.Nil, err
					}

					connect_file_set, flag := userlib.DatastoreGet(tmp_share.Fuuid)
					if !flag {
						err = fmt.Errorf("datastore has been modified")
						return uuid.Nil, err
					}
					connect_file_cipher := connect_file_set[:len(connect_file_set)-64]
					connect_file_hmac := connect_file_set[len(connect_file_set)-64:]

					hmac_key, err = userlib.HashKDF(tmp_share.Fsyskey[:16],
						[]byte(tmp_share.Fuuid.String()))
					cur_connect_file_hmac, err := userlib.HMACEval(hmac_key[:16], connect_file_cipher)

					switch {
					case err != nil: //signature check
						return uuid.Nil, err
					case !userlib.HMACEqual(cur_connect_file_hmac, connect_file_hmac): //check connect_file_hmac
						err = fmt.Errorf("file has been modifed")
						return uuid.Nil, err
					default: //decrypt
						json.Unmarshal(userlib.SymDec(tmp_share.Fsyskey[:16], connect_file_cipher), filestruct)
						if filestruct.Owner == recipientUsername {
							err = fmt.Errorf("this user has already owned the file")
							return uuid.Nil, err
						}
						privatekey = tmp_share.Secretkey
					}
				}
			}

			//contentkey, _ := userlib.HashKDF(filestruct.Content[:16], []byte("sym_content"+string(filestruct.Content)))
			//lastbytekey, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("sym_lastbyte"+string(filestruct.Last_byte)))
			hmac_key_content, _ := userlib.HashKDF(filestruct.Content[:16], []byte("hmac_content"+string(filestruct.Content)))
			hmac_key_lastbyte, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("hmac_lastbyte"+string(filestruct.Last_byte)))

			uidofcontent_cipher, _ := uuid.FromBytes(filestruct.Content[:16])
			content_cipher, _ := userlib.DatastoreGet(uidofcontent_cipher)
			uidoflastbyte_cipher, _ := uuid.FromBytes(filestruct.Last_byte[:16])
			lastbyte_cipher, _ := userlib.DatastoreGet(uidoflastbyte_cipher)

			hmac_content := content_cipher[len(content_cipher)-64:]
			hmac_lastbyte := lastbyte_cipher[len(lastbyte_cipher)-64:]
			content_cipher = content_cipher[:len(content_cipher)-64]
			lastbyte_cipher = lastbyte_cipher[:len(lastbyte_cipher)-64]

			expected_hmac_content, _ := userlib.HMACEval(hmac_key_content[:16], content_cipher)
			expected_hmac_lastbyte, _ := userlib.HMACEval(hmac_key_lastbyte[:16], lastbyte_cipher)

			//var ori_content []byte
			//var ori_lastbyte []byte

			switch {
			case !userlib.HMACEqual(hmac_content, expected_hmac_content):
				err = fmt.Errorf("file has been modified2")
				return uuid.Nil, err
			case !userlib.HMACEqual(hmac_lastbyte, expected_hmac_lastbyte):
				err = fmt.Errorf("file has been modified3")
				return uuid.Nil, err
			default:
				share_list_uid, _ := uuid.FromBytes([]byte(tmp_share.Fuuid.String())[:16])
				sharelist_set, flag := userlib.DatastoreGet(share_list_uid) // if this file has been shared
				sharelist := new(Share_list)
				sharelist.Owner_list = make(map[string]int)
				if flag {
					sharelist_cipher := sharelist_set[:len(sharelist_set)-64]
					sharelist_hmac := sharelist_set[len(sharelist_set)-64:]

					sharelist_key, _ := userlib.HashKDF([]byte(tmp_share.Fuuid.String())[:16], []byte("share_list_sym"))
					sharelist_hmac_key, _ := userlib.HashKDF([]byte(tmp_share.Fuuid.String())[:16], []byte("share_list_hmac"))

					expected_sharelist_hmac, _ := userlib.HMACEval(sharelist_hmac_key[:16], sharelist_cipher)
					switch {
					case !userlib.HMACEqual(expected_sharelist_hmac, sharelist_hmac):
						err = fmt.Errorf("sharelist has been modified")
						return uuid.Nil, err
					default:
						sharelist_plaintext := userlib.SymDec(sharelist_key[:16], sharelist_cipher)
						err := json.Unmarshal(sharelist_plaintext, sharelist)
						if err != nil {
							return uuid.Nil, err
						}

						if _, flag := sharelist.Owner_list[recipientUsername]; flag {
							err := fmt.Errorf("this user has already owned the file")
							return uuid.Nil, err
						} else {
							sharelist.Owner_list[recipientUsername] = 1
							sharelist_json, _ := json.Marshal(sharelist)
							sharelist_cipher = userlib.SymEnc(sharelist_key[:16], userlib.RandomBytes(16), sharelist_json)
							sharelist_hmac, _ = userlib.HMACEval(sharelist_hmac_key[:16], sharelist_cipher)

							userlib.DatastoreSet(share_list_uid, []byte(string(sharelist_cipher)+string(sharelist_hmac)))
						}
					}
				} else {
					sharelist.Owner_list[recipientUsername] = 1
					sharelist_json, _ := json.Marshal(sharelist)

					sharelist_key, _ := userlib.HashKDF([]byte(tmp_share.Fuuid.String())[:16], []byte("share_list_sym"))
					sharelist_hmac_key, _ := userlib.HashKDF([]byte(tmp_share.Fuuid.String())[:16], []byte("share_list_hmac"))

					sharelist_cipher := userlib.SymEnc(sharelist_key[:16], userlib.RandomBytes(16), sharelist_json)
					sharelist_hmac, _ := userlib.HMACEval(sharelist_hmac_key[:16], sharelist_cipher)

					userlib.DatastoreSet(share_list_uid, []byte(string(sharelist_cipher)+string(sharelist_hmac)))
				}
			}

			invitation_seed, _ := uuid.FromBytes(userlib.Hash(
				[]byte(recipientUsername + fuuid.String()))[:16])
			invitation, _ = uuid.FromBytes([]byte(invitation_seed.String()[:16]))
			sharestruct := new(share)
			sharestruct.Fuuid = fuuid
			sharestruct.Fsyskey = userdata.Keylist[filename]
			sharestruct.Secretkey = userdata.Privatekey

			sharestruct_json, _ := json.Marshal(sharestruct)
			recipient_publickey, flag := userlib.KeystoreGet(recipientUsername + "publickey")
			if !flag {
				err = fmt.Errorf("get publikey error")
				return uuid.Nil, err
			}
			//fmt.Println(recipientUsername + "publickey")
			//fmt.Println(recipient_publickey)
			//sharestruct_seed := userlib.RandomBytes(16)
			sharestruct_seed := userlib.Hash([]byte(recipientUsername + string(userdata.Sharesalt) + userdata.Username + filename))
			sharestruct_symkey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_sym_enc"))
			//sharestruct_hmackey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_hmac"))

			sharestruct_seed_cipher, _ := userlib.PKEEnc(recipient_publickey, sharestruct_seed)
			sharestruct_cipher := userlib.SymEnc(sharestruct_symkey[:16], userlib.RandomBytes(16), sharestruct_json)
			//sharestruct_hmac, _ := userlib.HMACEval(sharestruct_hmackey[:16], sharestruct_cipher)

			signature, _ = userlib.DSSign(userdata.Signaturekey, sharestruct_cipher)
			signature2, _ = userlib.DSSign(userdata.Signaturekey, sharestruct_seed_cipher)
			userlib.DatastoreSet(invitation, signature)
			//connect_file_hmac_uuid, _ := uuid.FromBytes([]byte((invitation.String() +
			//	string(signature)))[:16])
			//userlib.DatastoreSet(connect_file_hmac_uuid, filehmac)

			share_seed_uuid, _ := uuid.FromBytes([]byte((invitation.String() +
				string(signature)))[:16])
			sharestruct_cipher_uuid, _ = uuid.FromBytes(sharestruct_seed[:16])

			userlib.DatastoreSet(share_seed_uuid, []byte(string(sharestruct_seed_cipher)+string(signature2)))
			userlib.DatastoreSet(sharestruct_cipher_uuid, sharestruct_cipher)

			err = userdata.UserUpdate()
			if err != nil {
				return [16]byte{}, err
			}

			return invitation_seed, nil
		}
	} else {
		err = fmt.Errorf("filename error")
		return uuid.Nil, err
	}
}

func (userdata *User) AcceptInvitation(
	senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var err error
	userdata, err = userdata.UserLoad()
	if err != nil {
		return err
	}

	_, flag := userdata.Filelist[filename]
	if flag {
		err = fmt.Errorf("filename exsited")
		return err
	}

	filestruct := new(file)
	sharestruct := new(share)

	invitation, _ := uuid.FromBytes([]byte(invitationPtr.String())[:16])
	signature, _ := userlib.DatastoreGet(invitation)

	share_seed_uuid, _ := uuid.FromBytes([]byte((invitation.String() +
		string(signature)))[:16])

	sharestruct_seed_set, flag := userlib.DatastoreGet(share_seed_uuid)
	if !flag {
		err = fmt.Errorf("ds has been modified / revoke")
		return err
	}
	sharestruct_seed_cipher := sharestruct_seed_set[:len(sharestruct_seed_set)-256]
	sharestruct_seed_sig := sharestruct_seed_set[len(sharestruct_seed_set)-256:]

	verify_key, flag := userlib.KeystoreGet(senderUsername + "verifykey")
	if !flag {
		err = fmt.Errorf("get verifykey error")
		return err
	}

	err = userlib.DSVerify(verify_key,
		sharestruct_seed_cipher,
		sharestruct_seed_sig) //signature check
	if err != nil {
		fmt.Println("sig2 error")
		return err
	}

	sharestruct_seed, err := userlib.PKEDec(userdata.Privatekey, sharestruct_seed_cipher)
	if err != nil {
		return err
	}
	sharestruct_symkey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_sym_enc"))
	//sharestruct_hmackey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_hmac"))

	sharestruct_cipher_uuid, _ := uuid.FromBytes(sharestruct_seed[:16])
	sharestruct_cipher, flag := userlib.DatastoreGet(sharestruct_cipher_uuid)
	if !flag {
		err = fmt.Errorf("datastore has been modified2")
		return err
	}
	err = userlib.DSVerify(verify_key,
		sharestruct_cipher,
		signature) //signature check
	if err != nil {
		fmt.Println("sig error")
		return err
	}

	sharestruct_plaintext := userlib.SymDec(sharestruct_symkey[:16], sharestruct_cipher)
	//fmt.Println(userdata.Username + "privatekey")
	//fmt.Println(userdata.Privatekey)
	//if err != nil {
	//	fmt.Println("what the fuck2")
	//	return err
	//}
	err = json.Unmarshal(sharestruct_plaintext, sharestruct)
	if err != nil {
		return err
	}

	userdata.Filelist[filename] = uuid.New()
	//uuid.FromBytes([]byte(userdata.Username + filename +
	//string(userdata.Filesalt))[:16])
	userdata.Keylist[filename] = userlib.RandomBytes(16)
	hmac_key, _ := userlib.HashKDF(userdata.Keylist[filename][:16],
		[]byte(userdata.Filelist[filename].String()))

	filestruct.Flag = 1
	filestruct.Owner = senderUsername
	filestruct.Content = []byte(invitationPtr.String())

	new_file, _ := json.Marshal(filestruct)
	new_file_cipher := userlib.SymEnc(userdata.Keylist[filename][:16],
		userlib.RandomBytes(16),
		new_file,
	)
	new_file_hmac, _ := userlib.HMACEval(hmac_key[:16], new_file_cipher)
	userdata.Filehmaclist[filename] = new_file_hmac
	//userlib.DatastoreDelete(sharestruct_cipher_uuid)
	userlib.DatastoreSet(userdata.Filelist[filename], []byte(string(new_file_cipher)+string(new_file_hmac)))

	userdata.UserUpdate()

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	var err error
	userdata, err = userdata.UserLoad()
	if err != nil {
		return err
	}
	if fuuid, flag := userdata.Filelist[filename]; flag {
		filestruct_set, flag := userlib.DatastoreGet(fuuid)
		if !flag {
			err = fmt.Errorf("datastore has been modified")
			return err
		}

		filestruct_cipher := filestruct_set[:len(filestruct_set)-64]
		filestruct_hmac := filestruct_set[len(filestruct_set)-64:]

		hmac_key, _ := userlib.HashKDF(userdata.Keylist[filename][:16],
			[]byte(fuuid.String()))
		filehmac, _ := userlib.HMACEval(hmac_key[:16], filestruct_cipher)
		tmp_share := new(share)
		filestruct := new(file)

		switch {
		case !userlib.HMACEqual(filehmac, filestruct_hmac):
			err = fmt.Errorf("file has been modified")
			return err
		default:
			filestruct_plaintext := userlib.SymDec(userdata.Keylist[filename][:16], filestruct_cipher)

			//fmt.Println(string(filestruct_plaintext))

			err := json.Unmarshal(filestruct_plaintext, filestruct)
			if err != nil {
				return err
			}

			tmp_share.Fuuid = fuuid
			tmp_share.Fsyskey = userdata.Keylist[filename]
			privatekey := userdata.Privatekey

			var invitation uuid.UUID
			var signature []byte
			//var connect_file_hmac_uuid uuid.UUID
			var sharestruct_cipher_uuid uuid.UUID

			if filestruct.Owner == recipientUsername {
				err = fmt.Errorf("you cant revoke this user")
				return err
			}

			if filestruct.Flag != 0 {
				//shareflag = false
				for filestruct.Flag != 0 {
					invitation, _ = uuid.FromBytes(filestruct.Content[:16])
					signature, flag = userlib.DatastoreGet(invitation)
					if !flag {
						err = fmt.Errorf("datastore has been modified / you cant access to the file")
						return err
					}

					share_seed_uuid, _ := uuid.FromBytes([]byte((invitation.String() +
						string(signature)))[:16])
					//sharestruct_seed_cipher, flag := userlib.DatastoreGet(share_seed_uuid)
					//if !flag {
					//	err = fmt.Errorf("ds has been modified")
					//	return err
					//}

					sharestruct_seed_set, flag := userlib.DatastoreGet(share_seed_uuid)
					if !flag {
						err = fmt.Errorf("ds has been modified / revoke")
						return err
					}
					sharestruct_seed_cipher := sharestruct_seed_set[:len(sharestruct_seed_set)-256]
					sharestruct_seed_sig := sharestruct_seed_set[len(sharestruct_seed_set)-256:]

					verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
					if !flag {
						err = fmt.Errorf("get verifykey error")
						return err
					}

					err = userlib.DSVerify(verify_key,
						sharestruct_seed_cipher,
						sharestruct_seed_sig) //signature check
					if err != nil {
						fmt.Println("sig2 error")
						return err
					}

					sharestruct_seed, err := userlib.PKEDec(privatekey, sharestruct_seed_cipher)
					if err != nil {
						return err
					}
					sharestruct_symkey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_sym_enc"))
					//sharestruct_hmackey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_hmac"))

					sharestruct_cipher_uuid, _ = uuid.FromBytes(sharestruct_seed[:16])
					sharestruct_cipher, flag := userlib.DatastoreGet(sharestruct_cipher_uuid)
					if !flag {
						err = fmt.Errorf("datastore has been modified2")
						return err
					}
					//verify_key, flag := userlib.KeystoreGet(filestruct.Owner + "verifykey")
					//if !flag {
					//	err = fmt.Errorf("get verifykey error")
					//	return err
					//}
					err = userlib.DSVerify(verify_key,
						sharestruct_cipher,
						signature) //signature check
					if err != nil {
						fmt.Println("what the fuck1")
						return err
					}

					sharestruct_plaintext := userlib.SymDec(sharestruct_symkey[:16], sharestruct_cipher)
					err = json.Unmarshal(sharestruct_plaintext, tmp_share)
					if err != nil {
						return err
					}

					connect_file_set, flag := userlib.DatastoreGet(tmp_share.Fuuid)
					if !flag {
						err = fmt.Errorf("datastore has been modified")
						return err
					}
					connect_file_cipher := connect_file_set[:len(connect_file_set)-64]
					connect_file_hmac := connect_file_set[len(connect_file_set)-64:]

					hmac_key, err = userlib.HashKDF(tmp_share.Fsyskey[:16],
						[]byte(tmp_share.Fuuid.String()))
					cur_connect_file_hmac, err := userlib.HMACEval(hmac_key[:16], connect_file_cipher)

					switch {
					case err != nil: //signature check
						return err
					case !userlib.HMACEqual(cur_connect_file_hmac, connect_file_hmac): //check connect_file_hmac
						err = fmt.Errorf("file has been modifed")
						return err
					default: //decrypt
						json.Unmarshal(userlib.SymDec(tmp_share.Fsyskey[:16], connect_file_cipher), filestruct)
						if filestruct.Owner == recipientUsername {
							err = fmt.Errorf("you cant revoke this user")
							return err
						}
						privatekey = tmp_share.Secretkey
					}
				}

			}
		}
		hmac_key_content, _ := userlib.HashKDF(filestruct.Content[:16], []byte("hmac_content"+string(filestruct.Content)))
		hmac_key_lastbyte, _ := userlib.HashKDF(filestruct.Last_byte[:16], []byte("hmac_lastbyte"+string(filestruct.Last_byte)))

		uidofcontent_cipher, _ := uuid.FromBytes(filestruct.Content[:16])
		content_cipher, _ := userlib.DatastoreGet(uidofcontent_cipher)
		uidoflastbyte_cipher, _ := uuid.FromBytes(filestruct.Last_byte[:16])
		lastbyte_cipher, _ := userlib.DatastoreGet(uidoflastbyte_cipher)

		hmac_content := content_cipher[len(content_cipher)-64:]
		hmac_lastbyte := lastbyte_cipher[len(lastbyte_cipher)-64:]
		content_cipher = content_cipher[:len(content_cipher)-64]
		lastbyte_cipher = lastbyte_cipher[:len(lastbyte_cipher)-64]

		expected_hmac_content, _ := userlib.HMACEval(hmac_key_content[:16], content_cipher)
		expected_hmac_lastbyte, _ := userlib.HMACEval(hmac_key_lastbyte[:16], lastbyte_cipher)

		switch {
		case !userlib.HMACEqual(hmac_content, expected_hmac_content):
			err = fmt.Errorf("file has been modified2")
			return err
		case !userlib.HMACEqual(hmac_lastbyte, expected_hmac_lastbyte):
			err = fmt.Errorf("file has been modified3")
			return err
		default:
			share_list_uid, _ := uuid.FromBytes([]byte(tmp_share.Fuuid.String())[:16])
			sharelist_set, flag := userlib.DatastoreGet(share_list_uid) // if this file has been shared
			sharelist := new(Share_list)
			sharelist.Owner_list = make(map[string]int)
			if flag {
				sharelist_cipher := sharelist_set[:len(sharelist_set)-64]
				sharelist_hmac := sharelist_set[len(sharelist_set)-64:]

				sharelist_key, _ := userlib.HashKDF([]byte(tmp_share.Fuuid.String())[:16], []byte("share_list_sym"))
				sharelist_hmac_key, _ := userlib.HashKDF([]byte(tmp_share.Fuuid.String())[:16], []byte("share_list_hmac"))

				expected_sharelist_hmac, _ := userlib.HMACEval(sharelist_hmac_key[:16], sharelist_cipher)
				switch {
				case !userlib.HMACEqual(expected_sharelist_hmac, sharelist_hmac):
					err = fmt.Errorf("sharelist has been modified")
					return err
				default:
					sharelist_plaintext := userlib.SymDec(sharelist_key[:16], sharelist_cipher)
					err := json.Unmarshal(sharelist_plaintext, sharelist)
					if err != nil {
						return err
					}

					if v, _ := sharelist.Owner_list[recipientUsername]; v == 0 {
						err := fmt.Errorf("this user dosent own the file")
						return err
					} else {
						sharelist.Owner_list[recipientUsername] = 0
					}
				}
			} else {
				err = fmt.Errorf("no share / ds error")
				return err
			}
		}

		invitation_seed, _ := uuid.FromBytes(userlib.Hash(
			[]byte(recipientUsername + fuuid.String()))[:16])
		invitation, _ := uuid.FromBytes([]byte(invitation_seed.String()[:16]))

		//invitation, _ := uuid.FromBytes([]byte(invitationPtr.String())[:16])
		signature, ok := userlib.DatastoreGet(invitation)
		if !ok {
			err = fmt.Errorf("error1")
			return err
		}

		share_seed_uuid, _ := uuid.FromBytes([]byte((invitation.String() +
			string(signature)))[:16])
		//sharestruct_seed_cipher, flag := userlib.DatastoreGet(share_seed_uuid)
		//if !flag {
		//	err = fmt.Errorf("ds has been modified / revoke")
		//	return err
		//}

		sharestruct_seed_set, flag := userlib.DatastoreGet(share_seed_uuid)
		if !flag {
			err = fmt.Errorf("ds has been modified / revoke")
			return err
		}
		sharestruct_seed_cipher := sharestruct_seed_set[:len(sharestruct_seed_set)-256]
		sharestruct_seed_sig := sharestruct_seed_set[len(sharestruct_seed_set)-256:]

		verify_key, flag := userlib.KeystoreGet(userdata.Username + "verifykey")
		if !flag {
			err = fmt.Errorf("get verifykey error")
			return err
		}

		err = userlib.DSVerify(verify_key,
			sharestruct_seed_cipher,
			sharestruct_seed_sig) //signature check
		if err != nil {
			fmt.Println("sig2 error")
			return err
		}

		sharestruct_seed := userlib.Hash([]byte(recipientUsername + string(userdata.Sharesalt) + userdata.Username + filename))
		//if string(sharestruct_seed_cipher) != string(sharestruct_seed_cipher_1) {
		//	err = fmt.Errorf("error2")
		//	return err
		//}
		//sharestruct_seed_cipher, _ := userlib.PKEDec(recipient_publickey, sharestruct_seed_cipher)

		//sharestruct_seed, err := userlib.PKEDec(userdata.Privatekey, sharestruct_seed_cipher)
		//if err != nil {
		//	return err
		//}
		//sharestruct_symkey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_sym_enc"))
		//sharestruct_hmackey, _ := userlib.HashKDF(sharestruct_seed[:16], []byte("share_hmac"))
		sharestruct_cipher_uuid, _ := uuid.FromBytes(sharestruct_seed[:16])
		sharestruct_cipher, flag := userlib.DatastoreGet(sharestruct_cipher_uuid)
		if !flag {
			err = fmt.Errorf("datastore has been modified2")
			return err
		}
		//verify_key, flag := userlib.KeystoreGet(userdata.Username + "verifykey")
		//if !flag {
		//	err = fmt.Errorf("get verifykey error")
		//	return err
		//}
		err = userlib.DSVerify(verify_key,
			sharestruct_cipher,
			signature) //signature check
		if err != nil {
			fmt.Println("what the fuck1")
			return err
		}

		userlib.DatastoreDelete(invitation)
		err = userdata.UserUpdate()
		if err != nil {
			return err
		}
		return nil

	} else {
		err = fmt.Errorf("filename error")
		return err
	}
}
