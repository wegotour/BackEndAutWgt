package PasetoBackend

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

func TestCreateNewUserRole(t *testing.T) {
	var userdata User
	userdata.Email = "prisyahaura15@gmail.com"
	userdata.Password = "picaw"
	userdata.Role = "user"
	mconn := SetConnection("MONGOSTRING", "wegotour")
	CreateNewUserRole(mconn, "user", userdata)
}

func TestCreateNewAdminRole(t *testing.T) {
	var admindata Admin

	admindata.Email = "1214060@std.ulbi.ac.id"
	admindata.Password = "admin123"
	admindata.Role = "admin99"
	mconn := SetConnection("MONGOSTRING", "wegotour")
	CreateNewAdminRole(mconn, "admin", admindata)
}

func CreateNewUserToken(t *testing.T) {
	var userdata User
	userdata.Email = "faisalsidiq@gmail.com"
	userdata.Password = "sankuy"
	userdata.Role = "user"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "wegotour")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

func CreateNewAdminToken(t *testing.T) {
	var admindata User
	admindata.Email = "1214060@std.ulbi.ac.id"
	admindata.Password = "admin123"
	admindata.Role = "user"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "wegotour")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "admin", admindata)

	if err != nil {
		t.Errorf("Error creating admin and token: %v", err)
	}
}

func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Email = "faisal"
	userdata.Password = "sankuy"
	userdata.Role = "user"
	CreateNewUserRole(mconn, "user", userdata)
}

// PASETO
func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("wegotour", privateKey)
	fmt.Println(hasil, err)
}

func TestGenerateAdminPrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("admin", privateKey)
	fmt.Println(hasil, err)
}

func TestValidateToken(t *testing.T) {
	tokenstring := "53b5cacb30d005c380a6e5746c30b89775edcac2065c6407ec8949521731ff8779a6ff1d6d40bfc5f55864e79bd20c286f96fb64a8b9f92af28d40399a10058e" // Gantilah dengan token PASETO yang sesuai
	publicKey := "79a6ff1d6d40bfc5f55864e79bd20c286f96fb64a8b9f92af28d40399a10058e"
	payload, _err := watoken.Decode(publicKey, tokenstring)
	if _err != nil {
		fmt.Println("expired token", _err)
	} else {
		fmt.Println("ID: ", payload.Id)
		fmt.Println("Di mulai: ", payload.Nbf)
		fmt.Println("Di buat: ", payload.Iat)
		fmt.Println("Expired: ", payload.Exp)
	}
}

// Hash Pass
func TestGeneratePasswordHash(t *testing.T) {
	password := "bisabis15"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity
	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)

	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}

func TestGenerateAdminPasswordHash(t *testing.T) {
	password := "admin123"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}

func TestHashFunction(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Email = "daffa"
	userdata.Password = "pwnyapahayoh"

	filter := bson.M{"Email": userdata.Email}
	res := atdb.GetOneDoc[User](mconn, "admin", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(userdata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(userdata.Password, res.Password)
	fmt.Println("Match:   ", match)

}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Email = "prisyahaura"
	userdata.Password = "bisabis15"

	anu := IsPasswordValid(mconn, "admin", userdata)
	fmt.Println(anu)
}

// User
func TestInsertUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Email = "prisyahaura"
	userdata.Password = "picaw"

	nama := InsertUser(mconn, "user", userdata)
	fmt.Println(nama)
}

func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Email = "faisalsidiq14@gmail.com"
	userdata.Password = "sankuy"
	userdata.Role = "user"
	CreateUser(mconn, "user", userdata)
}

// Admin
func TestInsertUserAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Email = "prisyahaura"
	userdata.Password = "picaw"

	nama := InsertUser(mconn, "adin", userdata)
	fmt.Println(nama)
}

func TestAdminFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var admindata User
	admindata.Email = "11214041@std.ulbi.ac.id"
	admindata.Password = "admin123"
	admindata.Role = "admin"
	CreateUser(mconn, "user", admindata)
}

func TestIsAdminPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var admindata User
	admindata.Email = "11214041@std.ulbi.ac.id"
	admindata.Password = "admin123"

	anu := IsPasswordValid(mconn, "user", admindata)
	fmt.Println(anu)
}

func TestHashAdminFunction(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var admindata Admin
	admindata.Email = "admin@gmail.com"
	admindata.Password = "admin123"

	filter := bson.M{"email": admindata.Email}
	res := atdb.GetOneDoc[User](mconn, "admin", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(admindata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(admindata.Password, res.Password)
	fmt.Println("Match:   ", match)

}
