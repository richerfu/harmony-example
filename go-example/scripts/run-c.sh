#!/bin/bash

gcc ../go-shared/main.c -o main -L../go-shared -ladd

cp ../go-shared/libadd.dylib ./

./main
