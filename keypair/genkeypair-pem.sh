#!/bin/sh

# Key generation process as used by DMSAuthServer
openssl ecparam -name prime192v1 -out A1-prime192v1.pem
openssl ecparam -name prime192v1 -genkey -noout -out A2-pico_priv_key.pem
openssl pkcs8 -topk8 -inform PEM -outform DER -in A2-pico_priv_key.pem -out A3-pico_priv_key.der -nocrypt
openssl ec -in A2-pico_priv_key.pem -pubout -outform DER -out A4-pico_pub_key.der
rm *.pem

