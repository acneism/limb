# Common passwords

`common-passwords.txt` is the list of common passwords that the password policy rejects. It has one entry per line, sorted and without duplicates. Every entry is in NFKC form and lower case and is at least 8 characters long, because shorter passwords are rejected by the length rule anyway.

Source: [SecLists](https://github.com/danielmiessler/SecLists), file `Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt` at revision `180c2d55afa7aab8b18b7552f82dd0c92cc4ede5`. It holds the 100,000 most common passwords of the ten million passwords released by Mark Burnett, as described in the README of that directory. SecLists is distributed under the MIT license kept in `LICENSE` next to the list.

Filter: `internal/cmd/commonlist` trims every line, converts it to NFKC and lower case, drops the entries that are shorter than 8 characters, are not valid UTF-8 or contain control characters, removes duplicates and sorts the rest.

Result: 38451 entries, 355270 bytes.

To regenerate the list, run from the root of the repository:

```sh
curl -sS https://raw.githubusercontent.com/danielmiessler/SecLists/180c2d55afa7aab8b18b7552f82dd0c92cc4ede5/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt \
  | go run ./internal/cmd/commonlist > internal/password/data/common-passwords.txt
```
