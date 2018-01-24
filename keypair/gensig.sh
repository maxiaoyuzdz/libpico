#!/bin/sh

# Signature generation appropriate for DMSAuthServer
openssl dgst -sign pico_priv_key.der -keyform DER -sha256 -out data.new data.txt
base64 data.new > data.sig64

