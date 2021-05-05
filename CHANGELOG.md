## 0.1.x (2021-xxx-xx)

- Default opening notepad on windows when editting config or messages
- Service support: Now you can install both bm-bridge and bm-server as system services using bm-config
- bm-client: accounts can be activated and deactivated on the key resolver. Deactivated accounts will be removed after a while (not yet defined)
- bm-client: Reserved certain accounts and organisations for registration (see https://github.com/bitmaelum/bitmaelum-suite/wiki/reserved-addresses)
- bm-client: OTP generation works properly

# Security
- increased the ed25519 random seed from 192 to 256bits
- make sure the ed25519 keyexchange always outputs a 32byte key. Shorter keys were possible due to the non-zero extend of big.Int.
- defaulting to OAEP padding scheme

# Changes
- bm-bridge: It now uses a config file instead of parameters
- bm-bridge: Support for mail relay (aka gateway mode) for organizations, this way an organization can "host" using the BitMaelum protocol.
- bm-client: reserved certain accounts and organisations for registration (see https://github.com/bitmaelum/bitmaelum-suite/wiki/reserved-addresses)
- resolver configuration has been overhauled 
- bm-client: Added `--debug` flag to display HTTP traffic (override the client config's server.debughttp option) 



## 0.1.1-1 (2021-feb-19)

- Hotfix on the MSI packaging



## 0.1.1 (2021-feb-19)

- Added bm-bridge: This program will act as an IMAP/SMTP service between the bitmaelum network and regular email.
- Added bm-mail: This allows you to read your mail through a textual user interface (incomplete)

### Security
- <a href="https://github.com/bitmaelum/bitmaelum-suite/commit/3ce19bd0403202d8103f6ea4d964de2e1cccc9df">view commit</a>  &bull; Organisations have to be whitelisted before they are accepted on the server

### Changes
- bm-bridge: Added bm-bridge to connect bitmaelum to IMAP and SMTP (acalatrava)
- bm-client: Updated the account and organisation creation output to display the running steps
- bm-client: Added commands to manage organisation validations
- bm-client: Added command to query the resolver
- bm-client: Reading accounts in go-routines, this speeds up the reading of accounts a lot!
- lots of code cleanups (Eduaro Gomes)
- Updated makefile to display success/failures a lot better
- Dots and dashes are accepted in mail addresses, but not used
- Implemented initial encrypted store that is saved server-side. This can be used for settings, contacts, subscriptions and such. 



## 0.1.0 (2021-jan-21) 

Finalized "hello-world" release

### Security
- no issues found or fixed

### Changes
- Removed some obsolete tooling
- bm-client Organisations in bm-client can be suffixed with '!' so you can use either "foo" or "foo!" as organisation value.
- bm-client: Added functionality for managing organisation validations 
- bm-client: Added functionality to query info from the resolver 
- bm-client: "account create" and "organisation create" use a "step" layout for better feedback
- bm-client: reading messages is done concurrently, speeding it up a huge amount 

### Fixes
- bm-server: added whitelisting in config to only allow specific organisations to add accounts



## 0.0.2 (2021-jan-11)

Small update with some minor tweaks

### Security
-  no issues found or fixed

### Changes
- <a href="http://github.com/bitmaelum/bitmaelum-suite/commit/5ec838bca10fc0a898f76702230c29fb732719a4">view commit</a> &bull; "address" argument is now called "account" in all bm-client commands</li>
- <a href="http://github.com/bitmaelum/bitmaelum-suite/commit/945b7cfb997ac818b409d6b420e1634be0ddc0be">view commit</a> &bull; displaying mnmemonic if available in your account display</li>

### Fixes
- <a href="http://github.com/bitmaelum/bitmaelum-suite/commit/d7fd2281a96d4291d8b37c4e37bbeae9790df247">view commit</a>&bull; mandatory flag is called 'id' instead of 'message'</li>
- <a href="http://github.com/bitmaelum/bitmaelum-suite/commit/88ecab97d09aa5b912e12ea48693d1c1ccf7625d">view commit</a>&bull; #151: vault directories are now created when they do not exist</li> 



## 0.0.1 (2021-jan-10)

Initial developers-only release
