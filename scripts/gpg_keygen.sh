#!/bin/bash

keyfile=data/testkey.txt
username="Fred Smith, Jr."
email="fred@bla.com"
password="asdf1234"

echo "generating a new RSA key"
gpg --batch --gen-key <<EOF
Key-Type: 1
Key-Length: 2048
Subkey-Type: 1
Subkey-Length: 2048
Name-Real: ${username}
Name-Email: ${email}
Expire-Date: 0
Passphrase: ${password}
EOF

echo "exporting key to ${keyfile}"
#gpg --export-secret-key --export-options export-backup -a ${username} > ${keyfile}
gpg --batch --export-secret-keys --export-options export-backup --pinentry-mode=loopback --passphrase ${password} -a ${username} > ${keyfile}
#gpg --batch --export-secret-keys --pinentry-mode=loopback -a ${username} --passphrase ${password} > ${keyfile}

# now, delete the key
fingerprint=$(gpg --list-secret-keys 'Fred' | sed '2!d' | tr -d " ")
echo "removing key with fingerprint ${fingerprint}"
gpg --batch --yes --delete-secret-keys ${fingerprint}
gpg --batch --yes --delete-keys ${fingerprint}

