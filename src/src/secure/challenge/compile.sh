#!/bin/sh

gcc -Wall -g -o $1 $1.c -lssl -lcrypto &&
./$1

