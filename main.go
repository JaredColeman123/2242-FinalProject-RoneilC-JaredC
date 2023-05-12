package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"colemanjared.net/finalproject/finalproject/cookies"
)

func setCookie(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "ExampleCookie",
		Value:    "Hello World",
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)
	w.Write([]byte("This is a Simple Cookie Set!"))
}

func getCookie(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("ExampleCookie")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "No Cookie Found, Sorry", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
		}
		return
	}

	w.Write([]byte(cookie.Value))
}

func setCookieEncoded(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:  "ExampleCookie",
		Value: "你好",
	}

	err := cookies.Write(w, cookie)
	if err != nil {
		log.Println(err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	w.Write([]byte("Encoded Cookie Set!"))

}

func getCookieEncoded(w http.ResponseWriter, r *http.Request) {
	cookie, err := cookies.Read(r, "ExampleCookie")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "No Cookie Found", http.StatusBadRequest)
		case errors.Is(err, cookies.ErrInvalidValue):
			http.Error(w, "Invalid Cookie Value", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "Server Error", http.StatusInternalServerError)

		}
		return
	}
	w.Write([]byte(cookie))
}

var secretKey []byte

func setTamperProofCookie(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:  "ExampleCookie",
		Value: "Hello User! Secure Cookie Set",
	}

	err := cookies.WriteSigned(w, cookie, secretKey)
	if err != nil {
		log.Println(err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	w.Write([]byte("Secured Cookie Set!"))
}

func getTamperProofCookie(w http.ResponseWriter, r *http.Request) {
	value, err := cookies.ReadSigned(r, "ExampleCookie", secretKey)
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "Cookie Not Found", http.StatusBadRequest)
		case errors.Is(err, cookies.ErrInvalidValue):
			http.Error(w, "Invalid Cookie", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
		}
		return
	}
	w.Write([]byte(value))
}

func setEncryptedCookie(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:  "ExampleCookie",
		Value: "Hello User! Encrypted Cookie",
	}

	err := cookies.WriteEncrypted(w, cookie, secretKey)
	if err != nil {
		log.Println(err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Encrypted Cookie Set!"))
}

func getEncryptedCookie(w http.ResponseWriter, r *http.Request) {
	value, err := cookies.ReadEncrypted(r, "ExampleCookie", secretKey)
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "Cookie Not Found", http.StatusBadRequest)
		case errors.Is(err, cookies.ErrInvalidValue):
			http.Error(w, "Invalid Cookie", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "Server Error", http.StatusInternalServerError)

		}
		return
	}
	w.Write([]byte(value))
}

type User struct {
	Name string
	Age  int
}

func setTypeCookie(w http.ResponseWriter, r *http.Request) {
	user := User{Name: "Jared", Age: 20}
	var buf bytes.Buffer

	err := gob.NewEncoder(&buf).Encode(&user)

	if err != nil {
		log.Println(err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	cookie := http.Cookie{
		Name:  "ExampleCookie",
		Value: buf.String(),
	}

	err = cookies.WriteEncrypted(w, cookie, secretKey)

	if err != nil {
		log.Println(err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Custom Type Cookie Set!"))
}

func getTypeCookie(w http.ResponseWriter, r *http.Request) {
	gobEncodedValue, err := cookies.ReadEncrypted(r, "ExampleCookie", secretKey)
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "Cookie Not Found", http.StatusBadRequest)
		case errors.Is(err, cookies.ErrInvalidValue):
			http.Error(w, "Invalid Cookie", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
		}
		return
	}

	var user User
	reader := strings.NewReader(gobEncodedValue)

	err = gob.NewDecoder(reader).Decode(&user)

	if err != nil {
		log.Println(err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Name: %q\n", user.Name)
	fmt.Fprintf(w, "Age: %d\n", user.Age)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/set", setCookie)
	mux.HandleFunc("/get", getCookie)

	mux.HandleFunc("/setEncoded", setCookieEncoded)
	mux.HandleFunc("/getEncoded", getCookieEncoded)

	var err error

	secretKey, err = hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")

	if err != nil {
		log.Fatal(err)
	}

	mux.HandleFunc("/setSignedCookie", setEncryptedCookie)
	mux.HandleFunc("/getSignedCookie", getTamperProofCookie)

	mux.HandleFunc("/setEncryptedCookie", setEncryptedCookie)
	mux.HandleFunc("/getEncryptedCookie", getEncryptedCookie)

	gob.Register(&User{})

	mux.HandleFunc("/setTypeCookie", setTypeCookie)
	mux.HandleFunc("/getTypeCookie", getTypeCookie)

	log.Println("Starting on server on http://localhost:8000")
	err = http.ListenAndServe(":8000", mux)
	if err != nil {
		log.Fatal(err)
	}
}
