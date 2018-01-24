#!/bin/sh

openssl ecparam -name prime192v1 -out prime192v1.pem
openssl ecparam -name prime192v1 -genkey -noout -out pico_priv_key.pem
openssl pkcs8 -topk8 -inform PEM -outform DER -in pico_priv_key.pem -out pico_priv_key.der -nocrypt
openssl ec -in pico_priv_key.pem -pubout -outform DER -out pico_pub_key.der
rm *.pem

