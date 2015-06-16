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
	"github.com/dgryski/dgoogauth"
	"github.com/seehuhn/password"
	"github.com/atotto/clipboard"
	"flag"
)

//Secretbox demo: http://play.golang.org/p/SRq2AqA4Dz
//terminal: http://godoc.org/code.google.com/p/go.crypto/ssh/terminal
//gob encoding http://play.golang.org/p/frZq8YbcAb

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

var clipFlag = flag.Bool("clip", false, "Copy password and code to clipboard (useful for OSX Yosemite with broken scutil)")
//var configFlag = flag.Bool("config", false, "Decrypt and print config")

func main() {

	fmt.Println("In OSX Yosemite, I've found the scutil command is broken, so it won't accept the password parameter properly... This causes the VPN not to start and a password dialog to appear. If this is the case for you, use the -clip flag. This will copy your password / auth code to the clipboard each time we attempt to start the VPN. Just paste into the password dialog and the VPN should start correctly.\n")

	flag.Parse()

	config, err := readConfigFromFile()

	//if *configFlag {
	//	fmt.Printf("%#v\n\n", config)
	//}

	if err != nil {
		fmt.Println("Can't find config file (or error loading)... We will make a new config file...\n")
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

	fmt.Println("Press enter to start VPN")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {

		codeNow := dgoogauth.ComputeCode(config.Secret, int64(time.Now().Unix()/30))
		fmt.Printf("Code: %06d\n", codeNow)

		cmd := exec.Command("scutil", "--nc", "start", config.VpnName, "--user", config.Username, "--password", config.Password+fmt.Sprintf("%06d", codeNow))
		err := cmd.Start()
		if err != nil {
			log.Fatal(err)
		}

		err = cmd.Wait()
		if err != nil {
			fmt.Println("Error while starting VPN.")
		} else {
			fmt.Println("VPN starting...")
			if *clipFlag {
				fmt.Println("Password and auth code copied to clipboard.")
				clipboard.WriteAll(config.Password+fmt.Sprintf("%06d", codeNow))
			}
		}

		fmt.Println("\nPress enter to start the VPN again.")

	}

}

func getFilename() string {
	usr, _ := user.Current()
	dir := usr.HomeDir
	return dir + "/.govpn-config.json"
}

func getConfigFromUser() PlainConfig {

	fmt.Println("This will ask you for a bunch of details, and encrypt the result in a config file: " + getFilename() + " \n")
	fmt.Println("Please do not back this file up online. The point of 2 factor auth is that you need one thing you know (your encryption password) and one physical thing you have (your laptop). If you back up the config file online, you no longer need something physical.\n")

	fmt.Println("Enter an encryption password. All the following details will be encrypted with this password")
	password1, err := password.Read("")

	if err != nil || len(password1) == 0 {
		log.Fatal(err)
	}

	fmt.Println("Enter your encryption password again")
	password2, err := password.Read("")

	if err != nil || len(password2) == 0 {
		log.Fatal(err)
	}

	if string(password1) != string(password2) {
		fmt.Println("Passwords don't match.")
		os.Exit(1)
	}

	buf := bufio.NewReader(os.Stdin)

	fmt.Println("When you set up your OSX native VPN, what name did you give it?")
	vpnName, err := buf.ReadString('\n')
	vpnName = vpnName[:len(vpnName)-1]

	if err != nil || len(vpnName) == 0 {
		log.Fatal(err)
	}

	buf = bufio.NewReader(os.Stdin)

	fmt.Println("What is your VPN username?")
	vpnUsername, err := buf.ReadString('\n')
	vpnUsername = vpnUsername[:len(vpnUsername)-1]

	if err != nil || len(vpnUsername) == 0 {
		log.Fatal(err)
	}

	fmt.Println("What is your VPN password?")
	vpnPassword, err := password.Read("")

	if err != nil || len(vpnPassword) == 0 {
		log.Fatal(err)
	}

	buf = bufio.NewReader(os.Stdin)

	fmt.Println("What is your Google Authenticator Secret?")
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

	fmt.Println("Great! found your config. What is your encryption password?")
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
