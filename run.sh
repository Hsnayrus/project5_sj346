#!/bin/bash

clear
make clean
make
rm sneaky_process
make sneaky_process
sudo ./sneaky_process
