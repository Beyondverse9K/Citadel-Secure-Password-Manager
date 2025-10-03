## Citadel Ubuntu Release (Cross-Platform Support soon!)
## Install Dependencies

`sudo apt install build-essential cmake libssl-dev xclip`

## Build Project

`git clone <https://github.com/Beyondverse9K/Citadel-Secure-Password-Manager>`

`cd Citadel-Secure-Password-Manager`

`mkdir build`

`cd build`

`cmake ..`

`make`

## Run Project

`HASH=$(sha256sum ./Citadel-Secure-Password-Manager | awk '{ print $1 }')`

`echo $HASH`

`sed -i "s/MY_BINARY_HASH/$HASH/" ../src/security.c`

`make`

`./Citadel-Secure-Password-Manager`

## Core Functionality

Secure Vault Storage: The application saves all credential data to a single encrypted file named vault.db.

Credential Management: You can perform full CRUD (Create, Read, Update, Delete) operations on your passwords.

Password Generation: There's a feature to generate strong, 20-character random passwords using a wide character set for enhanced security.

Dynamic Storage: The vault can grow as you add more credentials, automatically reallocating memory as needed to accommodate a larger number of entries.

## Security Features

Strong Encryption: Your data is encrypted using AES-256-GCM, an industry-standard algorithm that provides both confidentiality and data integrity.

Secure Key Derivation: Master passwords are not used directly as encryption keys. Instead, they are processed with a salted PBKDF2-HMAC-SHA256 function with a high iteration count (310,000) to create a strong key, making brute-force attacks difficult.

Anti-Debugger Detection: At startup, the program checks if it's being monitored by a debugger (like GDB) using the ptrace system call and will exit if one is detected.

Binary Integrity Check: The application verifies its own executable file against a hardcoded SHA-256 hash at launch. It will exit if it detects that the program file has been tampered with.

Secure Clipboard Wiping: When a password is copied, it is automatically cleared from the system clipboard after a 30-second timeout to prevent accidental exposure.

Secure Memory Handling: The code takes care to securely zero out sensitive data like derived encryption keys from memory as soon as they are no longer needed.

## User Interface Features

Command-Line Interface: The program operates through a simple, text-based menu system in the terminal.

Secret Password Entry: When you type your master password, the terminal echo is disabled, so your password is not displayed on the screen.

Full Credential Control: The menu provides clear options to list all credentials, find a specific one, add a new one, delete one, or generate a new password.
