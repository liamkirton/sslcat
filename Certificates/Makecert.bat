@echo off
makecert.exe -pe -n "CN=SslCat Root Authority" -ss my -sr LocalMachine -a sha1 -sky signature
makecert.exe -pe -n "CN=SslCat" -ss my -sr LocalMachine -a sha1 -sky exchange -eku 1.3.6.1.5.5.7.3.1 -in "SslCat Root Authority" -is MY -ir LocalMachine -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12
