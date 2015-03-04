package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"time"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/ssh/terminal"
	"github.com/dgryski/dgoogauth"
	"github.com/seehuhn/password"
)

type EncryptedConfig struct {
	Data  []byte
	Nonce [24]byte
}

type PlainConfig struct {
	VpnName  string
	Username string
	Password string
	Secret   string
}

func main() {

	//Secretbox demo: http://play.golang.org/p/SRq2AqA4Dz
	//terminal: http://godoc.org/code.google.com/p/go.crypto/ssh/terminal
	//gob encoding http://play.golang.org/p/frZq8YbcAb

	config, err := readConfigFromFile()

	if err != nil {
		fmt.Print("Can't find config file (or error loading)... We will make a new config file...\n\n")
		config = getConfigFromUser()
	}

	connect(config)

}

func SingleSHA(b []byte) [32]byte {
	h := sha256.New()
	h.Write(b)
	slice := h.Sum(nil)
	var arr [32]byte
	copy(arr[:], slice[:])
	return arr
}

func connect(config PlainConfig) {

	fmt.Print("Press enter to start VPN\n")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {

		codeNow := dgoogauth.ComputeCode(config.Secret, int64(time.Now().Unix()/30))
		//code2 := dgoogauth.ComputeCode(config.Secret, int64(time.Now().Add(time.Second*2).Unix()/30))
		//code5 := dgoogauth.ComputeCode(config.Secret, int64(time.Now().Add(time.Second*5).Unix()/30))
		//code10 := dgoogauth.ComputeCode(config.Secret, int64(time.Now().Add(time.Second*10).Unix()/30))

		//fmt.Printf("Code now    : %06d (starting VPN with this)\n", codeNow)
		//fmt.Printf("Code in 2s  : %06d (copied to clipboard)\n", code2)
		//fmt.Printf("Code in 5s  : %06d\n", code5)
		//fmt.Printf("Code in 10s : %06d\n", code10)

		//clipboard.WriteAll(fmt.Sprint(code2))
		cmd := exec.Command("scutil", "--nc", "start", config.VpnName, "--user", config.Username, "--password", config.Password+fmt.Sprintf("%06d", codeNow))
		err := cmd.Start()
		if err != nil {
			log.Fatal(err)
		}
		err = cmd.Wait()
		if err != nil {
			fmt.Print("Error while starting VPN. Is it already running?\n")
		} else {
			fmt.Print("VPN starting...\n")
		}

		fmt.Print("\n")
		//fmt.Print("Press enter to get a new code and start the VPN again\n")
		fmt.Print("Press enter to start the VPN again\n")

	}

}

func getFilename() string {
	usr, _ := user.Current()
	dir := usr.HomeDir
	return dir + "/.govpn-config.json"
}

func getConfigFromUser() PlainConfig {

	fmt.Print("This will ask you for a bunch of details, and encrypt the result in a config file: " + getFilename() + " \n\n")
	fmt.Print("Please do not back this file up online. The point of 2 factor auth is that you need one thing you know (your encryption password) and one physical thing you have (your laptop). If you back up the config file online, you no longer need something physical.\n\n")

	fmt.Print("Enter an encryption password. All the following details will be encrypted with this password\n")
	password1, err := password.Read("")

	if err != nil || len(password1) == 0 {
		log.Fatal(err)
	}

	fmt.Print("Enter your encryption password again\n")
	password2, err := password.Read("")

	if err != nil || len(password2) == 0 {
		log.Fatal(err)
	}

	if string(password1) != string(password2) {
		fmt.Print("Passwords don't match.\n")
		os.Exit(1)
	}

	buf := bufio.NewReader(os.Stdin)

	fmt.Print("When you set up your OSX native VPN, what name did you give it?\n")
	vpnName, err := buf.ReadString('\n')
	vpnName = vpnName[:len(vpnName)-1]

	if err != nil || len(vpnName) == 0 {
		log.Fatal(err)
	}

	buf = bufio.NewReader(os.Stdin)

	fmt.Print("What is your VPN username?\n")
	vpnUsername, err := buf.ReadString('\n')
	vpnUsername = vpnUsername[:len(vpnUsername)-1]

	if err != nil || len(vpnUsername) == 0 {
		log.Fatal(err)
	}

	fmt.Print("What is your VPN password?\n")
	vpnPassword, err := password.Read("")

	if err != nil || len(vpnPassword) == 0 {
		log.Fatal(err)
	}

	buf = bufio.NewReader(os.Stdin)

	fmt.Print("What is your Google Authenticator Secret?\n")
	googleSecret, err := password.Read("")

	if err != nil || len(googleSecret) == 0 {
		log.Fatal(err)
	}

	config := PlainConfig{
		VpnName:  vpnName,
		Username: vpnUsername,
		Password: string(vpnPassword),
		Secret:   string(googleSecret),
	}

	saveConfigToFile(password1, config)

	return config
}

func readConfigFromFile() (PlainConfig, error) {
	config := PlainConfig{}
	fileBytes, err := ioutil.ReadFile(getFilename())

	if err != nil {
		return config, err
	}

	fc := &EncryptedConfig{}

	err = json.Unmarshal(fileBytes, fc)

	if err != nil {
		return config, err
	}

	fmt.Print("Great! found your config. What is your encryption password?\n")
	password, _ := password.Read("")
	key := SingleSHA(password)

	var opened []byte
	opened, ok := secretbox.Open(opened, fc.Data, &fc.Nonce, &key)

	if !ok {
		log.Fatal("Failed to decrypt config")
	}

	decBuf := bytes.NewBuffer(opened)

	err = gob.NewDecoder(decBuf).Decode(&config)

	if err != nil {
		log.Fatal(err)
	}

	return config, nil
}

func saveConfigToFile(encryptionPassword []byte, config PlainConfig) {
	key := SingleSHA(encryptionPassword)

	var nonce [24]byte
	rand.Reader.Read(nonce[:])

	encBuf := new(bytes.Buffer)
	err := gob.NewEncoder(encBuf).Encode(config)
	if err != nil {
		log.Fatal(err)
	}
	message1 := encBuf.Bytes()

	var box1 []byte
	box1 = secretbox.Seal(box1[:0], message1, &nonce, &key)

	fc := &EncryptedConfig{
		Data:  box1,
		Nonce: nonce,
	}

	data, err := json.Marshal(fc)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(getFilename(), data, 0644)

	if err != nil {
		log.Fatal(err)
	}

	return

}

func StringPrompt() (password string, err error) {
	state, err := terminal.MakeRaw(0)
	if err != nil {
		log.Fatal(err)
	}
	defer terminal.Restore(0, state)
	term := terminal.NewTerminal(os.Stdout, "")
	password, err = term.ReadLine()
	if err != nil {
		log.Fatal(err)
	}
	return
}
