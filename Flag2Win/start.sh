#!/bin/sh

export FLAG='TSGCTF{CRYPTO_IS_LOCK._KEY_IS_OPEN._CTF_IS_FUN!}'

while :
do
	socat -d tcp-listen:35719,reuseaddr,fork exec:"ruby /Flag2Win/flag_to_win.rb",stderr
done
