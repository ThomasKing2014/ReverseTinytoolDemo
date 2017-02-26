# For protected ELF32 file
# Author: ThomasKing
# Date: 2015.01.02

import struct
import sys
import os

ELF_MAGIC = '\x7f\x45\x4c\x46'
DT_STRTAB = 5
DT_STRSZ  = 10
DT_SYMTAB = 6
DT_REL 	  = 17
DT_RELSZ  = 18
DT_JMPREL	= 23
DT_PLTRELSZ	= 2
DT_HASH   = 4
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAY = 26
DT_FINI_ARRAYSZ = 28
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33

try:
	from awesome_print import ap as pp
except:
	from pprint import pprint as pp

try:
	from idaapi import *
	from idautils import *
	from idc import *
	IN_IDA = True
except:
	print "Not running in IDA?"
	IN_IDA = False

def SearchGotEnd(data, start, end, rels):
	for i in range(end, start, -1):
		num = struct.unpack('<I', data[i - 4 : i])
		for j in range(len(rels)):
			if num == rels[j].r_offset:
				return i
	return 0
	
def SearchPltStart(data):
	return data.find('\x04\xE0\x2D\xE5\x04\xE0\x9F\xE5\x0E\xE0\x8F\xE0\x08\xF0\xBE\xE5')
	
def SearchTextEnd(data):
	return data.find('\x08\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00Android')
	
def SearchRODATA(data, start, end):
	ret_start = -1
	ret_len	= -1
	for i in range(end - start):
		if data[start + i].isalnum():
			ret_start = start + i
			break;
	if ret_start == -1:
		return [ret_start, ret_len]
	'''
	current = ret_start
	while(current < end):
		if not data[current].isalnum():
			hitEndding = True
			for i in range(24):
				if data[current + i].isalnum():
					hitEndding = False
					break;
			if hitEndding:
				ret_len = current - ret_start
				break;
		current = current + 1
	'''
	return [ret_start & ~0x3, (ret_len + 0x3) & ~0x3]

class RelInfo:
	def __init__(self, name, r_offset, is_fun):
		self.name = name
		self.r_offset = r_offset
		self.is_fun = is_fun

class Section:
	def __init__(self, name, vaddr, vend, attr):
		self.name = name
		self.vaddr = vaddr
		self.vend = vend
		self.attr = attr
		
class ELF32Ehdr:
	def __init__(self, e_entry, e_phoff, e_phnum):
		self.e_entry = e_entry
		self.e_phoff = e_phoff
		self.e_phnum = e_phnum
		
class ELF32Phdr:
	def __init__(self, p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_flags):
		self.p_type   = p_type
		self.p_offset = p_offset
		self.p_vaddr  = p_vaddr
		self.p_filesz = p_filesz
		self.p_memsz  = p_memsz
		self.p_flags  = p_flags
		
class ELFImage:
	def __init__(self, f):
		f.seek(16, 0)
		(e_type,   e_machine, e_version,  e_entry,  
		 e_phoff,  e_shoff,   e_flags,    e_ehsize, 
		 e_phentsize, e_phnum,  e_shentsize, 
		 e_shnum,  e_shstrndx) = struct.unpack('<HHIIIIIHHHHHH', f.read(36))
		self.ehdr = ELF32Ehdr(e_entry, e_phoff, e_phnum)
		
		self.static_compile = True
		self.loads = []
		f.seek(e_phoff, 0)
		for i in range(e_phnum):
			(p_type, p_offset, p_vaddr, p_paddr, 
			p_filesz, p_memsz, p_flags, p_align) = struct.unpack('<IIIIIIII', f.read(32))
			if p_type == 1:
				self.loads.append(ELF32Phdr(p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
			if p_type == 2:
				self.dynamic = ELF32Phdr(p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_flags)
				self.static_compile = False
			if p_type == 0x70000001:
				self.arm_exidx = ELF32Phdr(p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_flags)
		
		if len(self.loads) != 2:
			print('Program segment modifed file, no analysis now!')
			return
		self.sections = []
		f.seek(self.loads[0].p_offset, 0)
		load0_data = f.read(self.loads[0].p_filesz)		
		if self.static_compile:
			print('*** This file is statically compiled! ***')
			text_offset = 52 + (self.ehdr.e_phoff - 52) + self.ehdr.e_phnum * 32
			text_offset = (text_offset + 0xf) & ~0xf
			text_vaddr = text_offset + self.loads[0].p_vaddr
			
			end_tag = SearchTextEnd(load0_data)
			if end_tag != -1:
				self.sections.append(Section('.note.android.ident', self.loads[0].p_vaddr + end_tag, self.arm_exidx.p_vaddr, 'DATA'))
			self.sections.append(Section('.text', text_vaddr, self.loads[0].p_vaddr + end_tag, 'CODE'))
			self.sections.append(Section('.arm.exidx', self.arm_exidx.p_vaddr, self.arm_exidx.p_vaddr + self.arm_exidx.p_filesz, 'DATA'))				
				
			[rodata_offset, rodata_len] = SearchRODATA(load0_data, self.arm_exidx.p_offset + self.arm_exidx.p_filesz, self.loads[0].p_offset + self.loads[0].p_filesz)
			if rodata_offset != -1:
				rodata_vaddr = rodata_offset + self.loads[0].p_vaddr
				self.sections.append(Section('.arm.extab',  self.arm_exidx.p_vaddr + self.arm_exidx.p_filesz, rodata_vaddr, 'DATA'))
			else:
				rodata_vaddr = self.arm_exidx.p_vaddr + self.arm_exidx.p_filesz
			self.sections.append(Section('.rodata', rodata_vaddr, self.loads[0].p_vaddr + self.loads[0].p_filesz, 'DATA'))
			self.sections.append(Section('.data', self.loads[1].p_vaddr, self.loads[1].p_vaddr + self.loads[1].p_filesz, 'DATA'))
			self.sections.append(Section('.bss', self.loads[1].p_vaddr + self.loads[1].p_filesz, self.loads[1].p_vaddr + self.loads[1].p_memsz, 'DATA'))
		else:
			f.seek(self.dynamic.p_offset, 0)
			for i in range(self.dynamic.p_filesz / 8):
				(d_tag, d_val) = struct.unpack('<II', f.read(8))
				if d_tag == DT_SYMTAB:
					symtab_vaddr = d_val
				elif d_tag == DT_STRTAB:
					strtab_vaddr = d_val
				elif d_tag == DT_STRSZ:
					strtabSize = d_val
				elif d_tag == DT_HASH:
					hashtab_vaddr = d_val
				elif d_tag == DT_INIT_ARRAY:
					initArray_vaddr = d_val
				elif d_tag == DT_INIT_ARRAYSZ:
					initArraySize = d_val
				elif d_tag == DT_FINI_ARRAY:
					finiArray_vaddr = d_val
				elif d_tag == DT_FINI_ARRAYSZ:
					finiArraySize = d_val
				elif d_tag == DT_PREINIT_ARRAY:
					preinitArray_vaddr = d_val
				elif d_tag == DT_PREINIT_ARRAYSZ:
					preinitArraySize = d_val
				elif d_tag == DT_REL:
					rel_vaddr = d_val
				elif d_tag == DT_RELSZ:
					relSize = d_val
				elif d_tag == DT_JMPREL:
					relPlt_vaddr = d_val
				elif d_tag == DT_PLTRELSZ:
					relPltSize = d_val
				else:
					pass
			f.seek(hashtab_vaddr - self.loads[0].p_vaddr, 0)
			[nbucket, nchain] = struct.unpack('<II', f.read(8))
			f.seek(symtab_vaddr - self.loads[0].p_vaddr, 0)
			symtab = f.read(nchain * 16)
			
			f.seek(strtab_vaddr - self.loads[0].p_vaddr, 0)
			strtab = f.read(strtabSize)
			
			f.seek(rel_vaddr - self.loads[0].p_vaddr, 0)
			rel = f.read(relSize)
			
			f.seek(relPlt_vaddr - self.loads[0].p_vaddr, 0)
			relPlt = f.read(relPltSize)
						
			f.seek(initArray_vaddr - self.loads[1].p_vaddr, 0)
			initArray = f.read(initArraySize)

			f.seek(finiArray_vaddr - self.loads[1].p_vaddr, 0)
			finiArray = f.read(finiArraySize)
			
			f.seek(preinitArray_vaddr - self.loads[1].p_vaddr, 0)
			preinitArray = f.read(preinitArraySize)			
			#
			plt_offset = SearchPltStart(load0_data)
			self.sections.append(Section('.plt', plt_offset + self.loads[0].p_vaddr, plt_offset + self.loads[0].p_vaddr + 20 + 12 * relPltSize / 8, 'CODE'))
			
			text_offset = plt_offset + 20 + 12 * relPltSize / 8
			text_vaddr = self.loads[0].p_vaddr + text_offset
			end_tag = SearchTextEnd(load0_data)
			
			if end_tag != -1:
				self.sections.append(Section('.note.android.ident', self.loads[0].p_vaddr + end_tag, self.arm_exidx.p_vaddr, 'DATA'))
			self.sections.append(Section('.text', text_vaddr, self.loads[0].p_vaddr + end_tag, 'CODE'))
			self.sections.append(Section('.arm.exidx', self.arm_exidx.p_vaddr, self.arm_exidx.p_vaddr + self.arm_exidx.p_filesz, 'DATA'))				
			
			[rodata_offset, rodata_len] = SearchRODATA(load0_data, self.arm_exidx.p_offset + self.arm_exidx.p_filesz, self.loads[0].p_offset + self.loads[0].p_filesz)
			if rodata_offset != -1:
				rodata_vaddr = rodata_offset + self.loads[0].p_vaddr
				self.sections.append(Section('.arm.extab',  self.arm_exidx.p_vaddr + self.arm_exidx.p_filesz, rodata_vaddr, 'DATA'))
			else:
				rodata_vaddr = self.arm_exidx.p_vaddr + self.arm_exidx.p_filesz
			self.sections.append(Section('.rodata', rodata_vaddr, self.loads[0].p_vaddr + self.loads[0].p_filesz, 'DATA'))	
			self.sections.append(Section('.init_array', initArray_vaddr, initArray_vaddr + initArraySize, 'DATA'))
			self.sections.append(Section('.fini_array', finiArray_vaddr, finiArray_vaddr + finiArraySize, 'DATA'))
			self.sections.append(Section('.preinit_array', preinitArray_vaddr, preinitArray_vaddr + preinitArraySize, 'DATA'))
			
			self.rels = []			
			for i in range(0, relPltSize, 8):
				[r_offset, r_info] = struct.unpack('<II', relPlt[i: i+8])
				sym_index = r_info >> 8
				[st_name, st_value] = struct.unpack('<II', symtab[sym_index * 16: sym_index * 16 + 8])
				tail = findCstringTail(strtab[st_name : len(strtab)])
				st_name = strtab[st_name: st_name + tail]
				self.rels.append(RelInfo(st_name, r_offset, True))				
			
			f.seek(self.loads[1].p_offset, 0)
			load1_data = f.read(self.loads[1].p_filesz)
			got_end_offset = SearchGotEnd(load1_data, preinitArray_vaddr + preinitArraySize - self.loads[1].p_vaddr, self.loads[1].p_filesz, self.rels)
			if got_end_offset == 0:
				self.sections.append(Section('.got', preinitArray_vaddr + preinitArraySize, self.loads[1].p_vaddr + self.loads[1].p_filesz, 'DATA'))
			else:
				self.sections.append(Section('.got', preinitArray_vaddr + preinitArraySize, self.loads[1].p_vaddr + got_end_offset, 'DATA'))
				self.sections.append(Section('.data', preinitArray_vaddr + preinitArraySize, self.loads[1].p_vaddr + got_end_offset, 'DATA'))
			self.sections.append(Section('.bss', self.loads[1].p_vaddr + self.loads[1].p_filesz, self.loads[1].p_vaddr + self.loads[1].p_memsz, 'DATA'))
			
def findCstringTail(str):
	retval = -1

	for i in range(0, len(str)):
		if str[i] == '\x00':
			retval = i
			break
	return retval

def accept_file(f, n):
	retval = 0
	if n == 0:
		f.seek(0)
		if f.read(4) == ELF_MAGIC:
			retval = "ELF32ARM<Bin> By ThomasKing"
	return retval

def load_file(f, neflags, format):
	print('------------Log begin ---------------')
	f.seek(0)
	elf = ELFImage(f)
	idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)
	
	for i in range(len(elf.loads)):
		f.file2base(elf.loads[i].p_offset, elf.loads[i].p_vaddr, elf.loads[i].p_vaddr + elf.loads[i].p_filesz, 1)
		if len(elf.loads) != 2:
			if elf.loads[i].p_flags & 0x1 == 1:
				add_segm(0, elf.loads[i].p_vaddr, elf.loads[i].p_vaddr + elf.loads[i].p_filesz, ('load%d' %i), 'CODE')
			else:
				add_segm(0, elf.loads[i].p_vaddr, elf.loads[i].p_vaddr + elf.loads[i].p_filesz, ('load%d' %i), 'DATA')
	if elf.ehdr.e_entry % 2 == 1:
		add_entry(elf.ehdr.e_entry & ~(0x1), elf.ehdr.e_entry & ~(0x1), 'start', 0)
	else:
		add_entry(elf.ehdr.e_entry, elf.ehdr.e_entry, 'start', 1)	
	
	if len(elf.loads) != 2:
		return 1
	for i in range(len(elf.sections)):
		add_segm(0, elf.sections[i].vaddr, elf.sections[i].vend, elf.sections[i].name, elf.sections[i].attr)
	
	if not elf.static_compile:
		extern_vaddr = elf.loads[1].p_vaddr + elf.loads[1].p_memsz
		add_segm(0, extern_vaddr, extern_vaddr + len(elf.rels) * 4, 'extern', 'XTRN')

		for i in range(len(elf.rels)):
			MakeDword(extern_vaddr + i * 4)
			MakeName(extern_vaddr + i * 4, '__imp_' + elf.rels[i].name)
			MakeName(elf.rels[i].r_offset, elf.rels[i].name + '_ptr')
			PatchDword(elf.rels[i].r_offset, extern_vaddr + i * 4)
	
	print('------------Log end ---------------')
	return 1
