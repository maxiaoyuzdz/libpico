#!/bin/sh

# Read in a public key (in the format sent in the StartMessage) and output it in PEM format
base64 -d pubkey.txt > pubkey.dat
openssl ec -pubin -inform DER -in pubkey.dat -outform PEM -out pubkey.pem

