#include <stdio.h>
#include <LIEF/LIEF.hpp>

int main(int argc, char** argv) {
	// Elf_Binary_t* elf = elf_parse("/usr/bin/ls");

	if(argc <= 1){
		return 0;
	}

	Elf_Binary_t* elf = elf_parse(argv[1]);

	Elf_Section_t** sections = elf->sections;
	for (size_t i = 0; sections[i] != NULL; ++i) {
		printf("%s\n", sections[i]->name);
	}

	elf_binary_destroy(elf);
	return 0;
}
