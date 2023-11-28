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

// PASETO
func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("wegotour", privateKey)
	fmt.Println(hasil, err)
}
func TestValidateToken(t *testing.T) {
	tokenstring := "eyJleHAiOiIyMDIzLTEwLTI2VDA1OjAyOjQ1WiIsImlhdCI6IjIwMjMtMTAtMjZUMDM6MDI6NDVaIiwiaWQiOiJkYWZmYSIsIm5iZiI6IjIwMjMtMTAtMjZUMDM6MDI6NDVaIn3cLq58WoqF4cfwdtKZiUas4-p4PVbwDaF4sa0QConAH_hZWT726D8" // Gantilah dengan token PASETO yang sesuai
	publicKey := "34984c89d5553bd07ced0b9ed6306cc010418a1758fae39e92bfce521ee7b44e"
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

// Admin
func TestInsertUserAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Email = "prisyahaura"
	userdata.Password = "picaw"

	nama := InsertUser(mconn, "adin", userdata)
	fmt.Println(nama)
}
