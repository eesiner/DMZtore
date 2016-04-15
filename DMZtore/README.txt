This folder contains all the files needed for the entire project.



The folder called 'archive' contains the individual files that builds the client 
**NOTE: Individual files in archive folder does not combine to form the final product.
**They merely contain the individual components needed to build the final product.



The folder called 'crypto_lib_for_arm_gcc' contains the cyrpto library for the Western Digital Cloud SERVER.
**NOTE: Inside contains another README.txt**



To Compile the final product, use this command:

gcc gui.c -o gui.exe `pkg-config --libs --cflags gtk+-2.0` -lgf_complete -lcrypto -lJerasure

To compile the server.c for WD servers, use this command:
arm-linux-gnueabi-gcc server.c -o server_arm.exe -lcrypto

To compile the server.c for local, use this command:
gcc server.c -o server_arm.exe -lcrypto

**NOTE Depending on which platform you are compiling for, change the name of the network adapter in server.c accordingly.

**Read the report for the requirements needed for the environment to run this command.
**Alternatively, you may download the entire VM image here - https://drive.google.com/open?id=0B0wlfCW-7N3zNzFRUnBCaGxVZ0E



