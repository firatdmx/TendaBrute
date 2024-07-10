# Router Brute Force Tool for Tenda V12 AC1200 VDSL

This project is a tool designed to perform a brute-force attack on the Tenda V12 AC1200 VDSL router's login page to find the correct password. Please use this tool responsibly and only on networks you have permission to test.

**Note:** I created this project because I forgot my own admin password and needed a way to regain access to my router.It is still under development and open to improvements. Contributions and feedback are welcome to help enhance its functionality and reliability.

## Features

- Reads a list of passwords from a specified file.
- Attempts to log in with each password.
- Changes the IP address after every 3 attempts to avoid getting locked.
- If a correct password is found, it prompts the user to navigate to the admin panel.
- Retries the skipped passwords in case of errors if no correct password is found after testing all passwords.
- Provides an option to re-enable DHCP on the specified network interface since it uses static IP addresses.
- Displays progress, status, and the current passphrase being tested.

## Prerequisites

- Python 3.x
- `requests` library
- `tkinter` library

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/router-brute-force-tool.git
cd router-brute-force-tool
```

https://github.com/firatdmx/TendaBrute/assets/65547262/80df38d4-ae6f-422d-be30-7e69ca2e713e

