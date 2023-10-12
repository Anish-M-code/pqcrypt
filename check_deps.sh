#!/bin/bash

has_command() {
 which "$1" $1 > /dev/null 2>&1
}


build_liboqs() {
	git clone -b main https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	mkdir -p build && cd build
	cmake -GNinja .. -DBUILD_SHARED_LIBS=ON
	ninja
	sudo ninja install
	cd ..
}

make_venv() {
	if ! [ -d ~/.pqcryptvenv ]; then
		mkdir -p ~/.pqcryptvenv
		printf "Making Python Virtual Environment"
		python3 -m venv ~/.pqcryptvenv
		source ~/.pqcryptvenv/bin/activate
	else
		source ~/.pqcryptvenv/bin/activate
	fi
}

apt_system() {
	printf "Debian/Ubuntu based found!!\n\n"
	sudo apt-get update
	sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml python3-pip git python3-venv
}

dnf_system() {
	printf "Fedora based system!!\n\n"
	sudo dnf install astyle cmake gcc-c++ ninja-build openssl-devel python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml python3-pip git python3
}

pacman_system() {
	printf "Arch Linux based found!!\n\n"
	sudo pacman -S astyle cmake gcc ninja python-pytest python-pytest-xdist unzip libxslt doxygen graphviz python-yaml python-pip git openssl python-cryptography python-argon2_cffi
}

make_venv

if has_command apt-get; then
  apt_system
elif has_command dnf; then
  dnf_system
elif has_command pacman; then
  pacman_system
else
  printf "\n\nDistribution not yet supported!\n\n"
fi

if ! [ -d /usr/local/include/oqs ]; then
	build_liboqs
else
	printf "\n\nliboqs already built, not rebuilding!\n\n"
fi

deactivate
