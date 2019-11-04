cmake_minimum_required(VERSION 3.5)

project(ipscanner LANGUAGES C)

add_executable(ipscanner main.c arp.c arp.h)
