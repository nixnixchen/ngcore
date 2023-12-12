#define _GNU_SOURCE

#include "elf_header.h"
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

const int ALIGN_SIZE = 4;

size_t addr_padding(size_t offset, size_t align_size)
{
	size_t padding = align_size - (offset  & (align_size - 1));
	return padding != align_size ? offset + padding: offset;
}

char* create_prstatus(struct elf_prstatus *main_thread_prstatus, pid_t thread_id, struct user_regs_struct reg)
{
	struct elf_prstatus *prstatus = (struct elf_prstatus *)malloc(sizeof(struct elf_prstatus));
	if(!prstatus){
		return NULL;
	}

	memcpy(prstatus, main_thread_prstatus, sizeof(struct elf_prstatus));
	memcpy(&(prstatus ->pr_reg), &reg, sizeof(struct user_regs_struct));

	// FIXME other info
	prstatus ->pr_pid = thread_id;

	return (char *) prstatus;
}

struct nt_prstatus{
	Elf64_Nhdr nhdr;
	char *pname;
	char *prstatus;
};

int copy_file(const char *src, const char *dst, off_t src_offset, off_t dst_offset, size_t size)
{
	int fd_src, fd_dst;
	int ret = -1;

	fd_src = open(src, O_RDONLY);
	if (fd_src < 0) {
		goto end;
	}

	if(dst_offset > 0){
		fd_dst = open(dst, O_WRONLY);
	}
	else{
		fd_dst = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	}

	if(fd_dst < 0) {
		goto close_src;
	}

	if(dst_offset > 0){
		ftruncate(fd_dst, dst_offset + size);
	}

	loff_t in_off = src_offset;
	loff_t out_off = dst_offset;

	while(size > 0){
		ssize_t n;

		n = copy_file_range(fd_src, &in_off, fd_dst, &out_off, size, 0);
		if (n < 0) {
			goto close_dst;
		}

		size -= n;
	}

close_dst:
	close(fd_dst);

close_src:
	close(fd_src);

end:
	return ret;
}

int reset_offset(char *core_file, int padding_size)
{
	Elf64_Ehdr* p_ehdr;
	Elf64_Phdr* p_phdr;
	p_ehdr = (Elf64_Ehdr *)core_file;
	int note_found = 0;

	for (int i = 0; i < p_ehdr ->e_phnum; i++) {
		p_phdr = (Elf64_Phdr *)(core_file + p_ehdr ->e_phoff + i * sizeof(*p_phdr));

		if (p_phdr ->p_type == PT_NOTE) {
			p_phdr ->p_filesz = p_phdr ->p_filesz + padding_size;
			note_found = 1;
		}
		else{
			if(note_found){
				p_phdr ->p_offset += padding_size;
			} 
		}
	}

	return 0;
}

int write_to_file(char *buff, const char *dst_file_name, size_t size)
{
	int fd_dst = open(dst_file_name, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if(fd_dst < 0) {
		return -1;
	}

	size_t block_size = 1024;
	size_t offset = 0;
	size_t n_write = 0;
	size_t bytes_to_write = 0;

	while(offset < size){
		bytes_to_write = (size - offset > block_size) ? block_size: size - offset;
		n_write = write(fd_dst, buff + offset, bytes_to_write);

		if(n_write == -1){
			break;
		}
		offset += n_write;
	}

	close(fd_dst);
	return offset >= size ? 0 : -1;
}

// https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html#note_section
int add_pr_note(const char* elf_tmp, const char* elf_final, int threadCnt, pid_t* tids, struct user_regs_struct* regs)
{
	int fd, i;
	int notes_offset = 0;
	int notes_size = 0;

	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;

	fd = open(elf_tmp, O_RDWR);
	if (fd < 0) {
		return -1;
	}

	size_t core_size = lseek(fd, 0, SEEK_END);
	char* core_file = mmap(NULL, core_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (core_file == MAP_FAILED) {
		return -1;
	}

	ehdr = *(Elf64_Ehdr *)core_file;
	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr = *(Elf64_Phdr *)(core_file + ehdr.e_phoff + i * sizeof(phdr));
		if (phdr.p_type == PT_NOTE) {
			notes_offset = phdr.p_offset;
			notes_size = phdr.p_filesz;
			break;
		}
	}

	size_t nhdr_size = sizeof(Elf64_Nhdr);
	size_t note_offset = notes_offset;
	struct elf_prstatus *main_thread_prstatus = NULL;

	size_t prstatus_note_size = 0;
	size_t prstatus_end_offset = 0;
	size_t prstatus_header_size = 0;
	size_t prstatus_note_start_offset = 0;

	while(note_offset < notes_offset + notes_size){
		Elf64_Nhdr *nhdr = (Elf64_Nhdr *)(core_file + note_offset);
		size_t name_end_offset = addr_padding(note_offset + nhdr_size + nhdr->n_namesz, ALIGN_SIZE);
		size_t desc_end_offset = addr_padding(name_end_offset + nhdr->n_descsz, ALIGN_SIZE);

		if (nhdr ->n_type == NT_PRSTATUS) {
			main_thread_prstatus = (struct elf_prstatus *)(core_file + name_end_offset);

			// reset signal
			main_thread_prstatus->pr_cursig = 0;
			main_thread_prstatus->pr_info.si_signo = 0;

			prstatus_note_size = desc_end_offset - note_offset;
			prstatus_note_start_offset = note_offset;

			prstatus_header_size = name_end_offset - note_offset;
			prstatus_end_offset = desc_end_offset;
		}

		note_offset = desc_end_offset;
	}

	if(!main_thread_prstatus){
		return -1;
	}

	size_t threads_info_size = prstatus_note_size * threadCnt;

	//STEP1 write Elf64_hdr
	reset_offset(core_file, threads_info_size);

	int ret = write_to_file(core_file, elf_final, prstatus_end_offset);
	if(ret < 0){
		return -1;
	}

	//STEP2 fill prstatus of other threads
	int core_out;
	core_out = open(elf_final,  O_WRONLY, 0644);
	if(!core_out){
		return -1;
	}

	lseek(core_out, 0, SEEK_END);
	for(int i = 0; i < threadCnt;i++){
		// make space for prstatus of other threads
		size_t bytes_written = write(core_out, core_file + prstatus_note_start_offset, prstatus_note_size);
		if(bytes_written != prstatus_note_size){
			exit(EXIT_FAILURE);
		}
	}

	size_t offset = prstatus_end_offset; 
	for(int i = 0; i < threadCnt;i++){
		size_t jumped = lseek(core_out, offset + prstatus_header_size, SEEK_SET);
		if(jumped < 0){
			return -1;
		}
		// printf("%d %ld %ld %d\n", tids[i], offset + prstatus_header_size, prstatus_end_offset + threads_info_size, threadCnt);

		char* prstauts = create_prstatus(main_thread_prstatus, tids[i], regs[i]);
		if(!prstauts){
			return -1;
		}

		// overwrite prstauts info
		size_t bytes_written = write(core_out, prstauts, sizeof(struct elf_prstatus));
		if(bytes_written != sizeof(struct elf_prstatus)){
			return -1;
		}

		free(prstauts);
		offset += prstatus_note_size;
	}
	close(core_out);

	// STEP3 copy the rest of original elf core dump
	copy_file(elf_tmp, elf_final, prstatus_end_offset, prstatus_end_offset + threads_info_size, core_size - prstatus_end_offset);

	if(munmap(core_file, core_size) == -1) {
		return -1;
	}

	close(fd);
	return 0;
}

