cmake_minimum_required(VERSION 3.19)
project(zedcrypt C)

set(CMAKE_C_STANDARD 99)

add_executable(zedcrypt main.c types.h sha/sha.h sha/consts.h sha/sha12.c sha/sha35.c aes/aes.c aes/aes.h mode/mode.c mode/mode.h)