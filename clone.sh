#!/bin/bash

chromeUA="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.111 Safari/537.36"
wget --no-check-certificate -O index.html -c -k -U "$chromeUA" "$1"
