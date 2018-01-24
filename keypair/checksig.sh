#!/bin/sh

# Signature check appropriate for DMSAuthServer
openssl dgst -verify pico_pub_key.der -keyform DER -signature data.sigbin data.txt 

