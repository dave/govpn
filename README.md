Google Authenticator VPN Starter
--------------------------------

If you have a Google Authenticator protected VPN, this will help you start it by just hitting enter. Also, your credentials are encrypted with [Secretbox](https://godoc.org/golang.org/x/crypto/nacl/secretbox).

So long as you don't back up the config file online, we still preserve the essence of 2 factor auth: you need something you know (your encryption password) and something physical you have (your laptop).

You need [Google Go](http://golang.org/doc/install) installed. To install govpn use go install:

```
go install github.com/davelondon/govpn
```

This will install the govpn command in your path. Then start it:

```
govpn
```

The first time it runs, it will prompt you for:

- An encryption password - make sure this is strong!
- The name of the VPN (you should set up a Mac native VPN, with a blank password).
- Your VPN password.
- Your Google Authenticator secret. You will probably need to request a new one from your security admin.

This data will be encrypted and stored in ```~/.govpn-config.json```. 

Simply press enter to connect or re-connect to te VPN.
