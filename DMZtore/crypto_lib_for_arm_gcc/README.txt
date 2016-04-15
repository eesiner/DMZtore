Client
======
Move libcrypto.so to /usr/arm-linux-gnueabi/lib/ 


Server
======
Upload libcrypto.so to server.
run 'cat /etc/ld.so.conf' to find shared library path
run 'cp libcrypto.so <path to the shared library'
run 'ldconfig' to update cache.
