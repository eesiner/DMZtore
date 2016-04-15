#!/bin/bash
for i in 10000 10001 10002
do
((SVR=$i-10000))
xterm -hold -e "rm -rf server$SVR;mkdir server$SVR;cp ./server.exe ./server$SVR/server.exe;cd server$SVR;./server.exe $i" &disown
done
