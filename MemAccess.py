from ctypes import *
from ctypes.wintypes import *
import os
import sys
import time

class MEMORY_BASIC_INFORMATION(Structure):
	_fields_ = [('BaseAddress', c_void_p),
	 ('AllocationBase', c_void_p),
	 ('AllocationProtect', DWORD),
	 ('RegionSize', c_size_t),
	 ('State', DWORD),
	 ('Protect', DWORD),
	 ('Type', DWORD)]

class MEMORY_BASIC_INFORMATION64(Structure):
	_fields_ = [('BaseAddress', c_ulonglong),
	 ('AllocationBase', c_ulonglong),
	 ('AllocationProtect', DWORD),
	 ('alignement1', DWORD),
	 ('RegionSize', c_ulonglong),
	 ('State', DWORD),
	 ('Protect', DWORD),
	 ('Type', DWORD),
	 ('alignement2', DWORD)]
	 
class SYSTEM_INFO(Structure):
	_fields_ = [('wProcessorArchitecture', WORD),
	 ('wReserved', WORD),
	 ('dwPageSize', DWORD),
	 ('lpMinimumApplicationAddress', LPVOID),
	 ('lpMaximumApplicationAddress', LPVOID),
	 ('dwActiveProcessorMask', c_ulonglong),
	 ('dwNumberOfProcessors', DWORD),
	 ('dwProcessorType', DWORD),
	 ('dwAllocationGranularity', DWORD),
	 ('wProcessorLevel', WORD),
	 ('wProcessorRevision', WORD)]
	
PAGE_EXECUTE_READWRITE = 64
PAGE_EXECUTE_READ = 32
PAGE_READONLY = 2
PAGE_READWRITE = 4
PAGE_NOCACHE = 512
PAGE_WRITECOMBINE = 1024
PAGE_GUARD = 256

MEM_COMMIT = 4096
MEM_FREE = 65536
MEM_RESERVE = 8192

class _TOKEN_ELEVATION(Structure):
	_fields_ = [
		("TokenIsElevated", DWORD),
	]
TOKEN_ELEVATION = _TOKEN_ELEVATION

class WinApi():
	def __init__(self):
		self.GetTokenInformation = windll.advapi32.GetTokenInformation
		self.GetTokenInformation.argtypes = [
			HANDLE, # TokenHandle
			c_uint, # TOKEN_INFORMATION_CLASS value
			c_void_p, # TokenInformation
			DWORD, # TokenInformationLength
			POINTER(DWORD), # ReturnLength
			]
		self.GetTokenInformation.restype = BOOL
		self.OpenProcessToken = windll.advapi32.OpenProcessToken
		self.OpenProcessToken.argtypes = (HANDLE, DWORD, POINTER(HANDLE))
		self.OpenProcessToken.restype = BOOL
		self.CreateToolhelp32Snapshot = CDLL("kernel32.dll").CreateToolhelp32Snapshot
		self.Process32First = CDLL("kernel32.dll").Process32First
		self.Process32Next = CDLL("kernel32.dll").Process32Next
		self.GetLastError = CDLL("kernel32.dll").GetLastError
		self.CloseHandle = CDLL("kernel32.dll").CloseHandle
		self.OpenProcess = CDLL("kernel32.dll").OpenProcess
		self.ReadProcessMemory = CDLL("kernel32.dll").ReadProcessMemory
		self.WriteProcessMemory = CDLL("kernel32.dll").WriteProcessMemory
		self.VirtualProtectEx = CDLL("kernel32.dll").VirtualProtectEx
		self._debug = False
		self._access = 0
		self._cache = {}
		self._cache_en = True
		
		si = self.GetNativeSystemInfo()
		self.max_addr = si.lpMaximumApplicationAddress
		self.min_addr = si.lpMinimumApplicationAddress
		
		self.FindWindow = windll.user32.FindWindowW
		self.SetWindowPos = windll.user32.SetWindowPos

	def set_topmost(self, classname, windowname):
		if (classname == "pygame"):
			print ("[+] WARNING: Setting the radar window as TOP MOST (ANTI-CHEAT RISK!)")
		hwnd = self.FindWindow(classname,windowname)
		if (hwnd == 0):
			raise RuntimeError("set_topmost: Could not find window")
		HWND_TOPMOST = -1
		SWP_NOMOVE = 0x0002
		SWP_NOSIZE = 0x0001
		ret = self.SetWindowPos(hwnd,HWND_TOPMOST,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE)
		if (ret == 0):
			raise RuntimeError("set_topmost: Could not set window as top-most")
				
	def is_elevated(self,phandle):
		token = HANDLE()
		TOKEN_QUERY = 0x0008
		res = self.OpenProcessToken(phandle, TOKEN_QUERY, token)
		if not res > 0:
			raise RuntimeError("Couldn't get process token")
		TokenElevationType = 18
		elev = DWORD(0)
		retlen = DWORD()
		res = self.GetTokenInformation( token, TokenElevationType , pointer(elev), sizeof(elev), pointer(retlen) )
		if not res > 0:
			raise RuntimeError("Couldn't get process token information")
		api.CloseHandle(token)
		return elev.value
		
	def get_processid_by_name(self,name):
		class PROCESSENTRY32(Structure):
			_fields_ = [ ( 'dwSize' , DWORD ) ,
						( 'cntUsage' , DWORD) ,
						( 'th32ProcessID' , DWORD) ,
						( 'th32DefaultHeapID' , POINTER(ULONG)) ,
						( 'th32ModuleID' , DWORD) ,
						( 'cntThreads' , DWORD) ,
						( 'th32ParentProcessID' , DWORD) ,
						( 'pcPriClassBase' , LONG) ,
						( 'dwFlags' , DWORD) ,
						( 'szExeFile' , c_char * 260 ) ]
		global api
		pid = 0
		snapshot = HANDLE(api.CreateToolhelp32Snapshot(DWORD(0x00000002),DWORD(0)))
		process = PROCESSENTRY32()
		process.cntUsage = 0
		process.th32ProcessID = 0
		process.th32ModuleID = 0
		process.cntThreads = 0
		process.th32ParentProcessID = 0
		process.pcPriClassBase = 0
		process.dwFlags = 0
		process.szExeFile = b""
		process.dwSize = sizeof(PROCESSENTRY32)
		
		i = 0
		pid = -1
		while 1:
			if (i==0):
				last = not api.Process32First(snapshot,byref(process))
			else:
				last = not api.Process32Next(snapshot,byref(process))
			procname = process.szExeFile
			if procname.decode("utf-8").lower() == name.lower():
				pid = process.th32ProcessID
				break
			
			if (last):
				break
			i+=1
		api.CloseHandle(snapshot)
		if (pid > -1):
			return pid
		return None
		
	def rpm_uint8(self,handle,addr):
		buffer = c_ubyte(0)
		addr_ = c_ulonglong(addr)
		ret = self.ReadProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		self._access+=1
		if (ret == 0):
			if (self._debug):
				print ("[+] ERROR: ReadProcessMemory Failed: 0x%x" %(self.GetLastError()))
				print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
			return 0
			#exit(1)
		if (self._debug): print ("rpm_uint8 -> addr: 0x%x val: 0x%x"%(addr,buffer.value))
		return buffer.value
		
	def rpm_uint16(self,handle,addr):
		buffer = c_ushort(0)
		addr_ = c_ulonglong(addr)
		ret = self.ReadProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		self._access+=1
		if (ret == 0):
			if (self._debug):
				print ("[+] ERROR: ReadProcessMemory Failed: 0x%x" %(self.GetLastError()))
				print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
			return 0
			#exit(1)
		if (self._debug): print ("rpm_uint16 -> addr: 0x%x val: 0x%x"%(addr,buffer.value))
		return buffer.value
		
	def rpm_uint32(self,handle, addr):
		buffer = c_ulong(0)
		addr_ = c_ulonglong(addr)
		ret = self.ReadProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		self._access+=1
		if (ret == 0):
			if (self._debug):
				print ("[+] ERROR: ReadProcessMemory Failed: 0x%x" %(self.GetLastError()))
				print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
			return 0
			#exit(1)
		if (self._debug): print ("rpm_uint32 -> addr: 0x%x val: 0x%x"%(addr,buffer.value))
		return buffer.value
		
	def rpm_int32(self,handle, addr):
		buffer = c_long(0)
		addr_ = c_ulonglong(addr)
		ret = self.ReadProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		self._access+=1
		if (ret == 0):
			if (self._debug):
				print ("[+] ERROR: ReadProcessMemory Failed: 0x%x" %(self.GetLastError()))
				print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
			return 0
			#exit(1)
		if (self._debug): print ("rpm_int32 -> addr: 0x%x val: 0x%x"%(addr,buffer.value))
		return buffer.value
		
	def rpm_float(self,handle, addr):
		buffer = c_float(0)
		addr_ = c_ulonglong(addr)
		ret = self.ReadProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		self._access+=1
		if (ret == 0):
			if (self._debug):
				print ("[+] ERROR: ReadProcessMemory Failed: 0x%x" %(self.GetLastError()))
				print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
			return 0
			#exit(1)
		if (self._debug): print ("rpm_float -> addr: 0x%x val: %f"%(addr,buffer.value))
		return buffer.value
		
		
	def rpm_uint64(self,handle, addr):
		#if ((self._cache_en) and (addr in self._cache)):
		#	return self._cache[addr]
		buffer = c_ulonglong(0)
		addr_ = c_ulonglong(addr)
		
		ret = self.ReadProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		#if (self._cache_en):
		#	self._cache[addr] = buffer.value
		self._access+=1
		
		if (ret == 0):
			if (self._debug):
				print ("[+] ERROR: ReadProcessMemory Failed: 0x%x" %(self.GetLastError()))
				print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
			return 0
			#exit(1)
		if (self._debug): print ("rpm_uint64 -> addr: 0x%x val: 0x%x"%(addr,buffer.value))
		return buffer.value
			
	def wpm_uint32(self,handle, addr, value):
		if (self._debug): print ("wpm_uint632 -> addr: 0x%x val: 0x%x"%(addr,value))
		buffer = c_ulong(value)
		addr_ = c_ulonglong(addr)
		ret = self.WriteProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		if (ret == 0):
			if (self._debug):
				print ("[+] ERROR: WriteProcessMemory Failed: 0x%x" %(self.GetLastError()))
				print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
			#exit(1)
			
	def wpm_uint64(self,handle, addr, value):
		if (self._debug): print ("wpm_uint64 -> addr: 0x%x val: 0x%x"%(addr,value))
		buffer = c_ulonglong(value)
		addr_ = c_ulonglong(addr)
		ret = self.WriteProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		if (ret == 0):
			if (self._debug):
				print ("[+] ERROR: WriteProcessMemory Failed: 0x%x" %(self.GetLastError()))
				print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
			#exit(1)
		
	def rpm_string(self,handle,addr):
		buffer = c_ulonglong(addr)
		str = ""		
		while (1):
			c = c_char()
			ret = self.ReadProcessMemory(handle,buffer,byref(c),sizeof(c),None)
			self._access+=1
			if (ret == 0):
				if (self._debug):
					print ("[+] ERROR: ReadProcessMemory Failed: 0x%x" %(self.GetLastError()))
					print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
				return ""
				#exit(1)
			if (c.value[0] == 0):
				break
			str += chr(c.value[0])
			buffer.value += 1
		if (self._debug): print ("rpm_uint64 -> addr: 0x%x val: %s"%(addr,str))
		return str	
		
		
	def rpm_pstring(self,handle,addr):
		buffer = c_ulonglong(0)
		addr_ = c_ulonglong(addr)
		ret = self.ReadProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		self._access+=1
		if (ret == 0):
			if (self._debug):
				print ("[+] ERROR: ReadProcessMemory Failed: 0x%x" %(self.GetLastError()))
				print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
			return ""
			#exit(1)
		str = ""		
		while (1):
			c = c_char()
			ret = self.ReadProcessMemory(handle,buffer,byref(c),sizeof(c),None)
			self._access+=1
			if (ret == 0):
				if (self._debug):
					print ("[+] ERROR: ReadProcessMemory Failed: 0x%x" %(self.GetLastError()))
					print ("[+] ERROR: Access of Address 0x%x failed" % (addr))
				return ""
				#exit(1)
			if (c.value[0] == 0):
				break
			str += chr(c.value[0])
			buffer.value += 1
		if (self._debug): print ("rpm_uint64 -> addr: 0x%x val: %s"%(addr,str))
		return str		
			
	def rpm_vec4(self,handle,addr):
		vec4 = c_float * 4
		buffer = vec4()
		addr_ = c_ulonglong(addr)
		ret = self.ReadProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		self._access+=1
		if (ret == 0):
			return 0
		return buffer
		
	def rpm_mat4(self,handle,addr):
		mat4 = (c_float * 4) * 4
		buffer = mat4()
		addr_ = c_ulonglong(addr)
		ret = self.ReadProcessMemory(handle,addr_,byref(buffer),sizeof(buffer),None)
		self._access+=1
		if (ret == 0):
			return 0
		return buffer
		
	def GetNativeSystemInfo(self):
		si = SYSTEM_INFO()
		windll.kernel32.GetNativeSystemInfo(byref(si))
		return si
		
	def VirtualQueryEx(self, handle, lpAddress):
		mbi = MEMORY_BASIC_INFORMATION()
		if not windll.kernel32.VirtualQueryEx(handle, LPCVOID(lpAddress), byref(mbi), sizeof(mbi)):
			print('Error VirtualQueryEx: 0x%08X 0x%08X' % (lpAddress,GetLastError()))
		return mbi
		
	def VirtualQueryEx64(self, handle, lpAddress):
		mbi = MEMORY_BASIC_INFORMATION64()
		if not windll.kernel32.VirtualQueryEx(handle, LPCVOID(lpAddress), byref(mbi), sizeof(mbi)):
			raise ProcessException('Error VirtualQueryEx: 0x%08X' % lpAddress)
		return mbi
		
	def iter_region(self, handle,start_offset=None, end_offset=None, protec=None, optimizations=None):
		
		offset = start_offset or self.min_addr
		end_offset = end_offset or self.max_addr

		while True:
			if offset >= end_offset:
				break
			mbi = self.VirtualQueryEx64(handle,offset)
			offset = mbi.BaseAddress
			chunk = mbi.RegionSize
			protect = mbi.Protect
			state = mbi.State
			if state & MEM_FREE or state & MEM_RESERVE:
				offset += chunk
				continue
			if protec:
				if not protect & protec or protect & PAGE_NOCACHE or protect & PAGE_WRITECOMBINE or protect & PAGE_GUARD:
					offset += chunk
					continue
			yield offset, chunk
			offset += chunk

class MemAccess(object):
	def __init__(self,pHandle):
		self.pHandle = pHandle
		
	def __getitem__(self,key):
		self.next_base = key
		if not self.isValid(key):
			#print ("Ptr Validity Error: 0x%x"%key)
			self.next_base = 0
		return self
		
	def __call__(self,key=0):
		if not self.isValid(self.next_base):
			#print ("Ptr Validity Error: 0x%x"%key)
			self.next_base = 0
			return self
		value = api.rpm_uint64(self.pHandle,key+self.next_base)
		self.next_base = value
		return self
		
	def isValid(self,addr):
		return ((addr >= 0x10000) and (addr < 0x000F000000000000));
		
	def me(self):
		if not self.isValid(self.next_base):
			return 0
		return self.next_base
		
	def weakptr(self,addr):
		self.next_base = api.rpm_uint64(self.pHandle,addr+self.next_base)
		if not self.isValid(self.next_base):
			self.next_base = 0
			return self
		self.next_base = api.rpm_uint64(self.pHandle,self.next_base)-0x8
		if not self.isValid(self.next_base):
			self.next_base = 0
			return self
		return self
		
	def read_uint8(self,off=0):
		if not self.isValid(self.next_base):
			return 0
		value = api.rpm_uint8(self.pHandle,off+self.next_base)
		return value
		
	def read_uint16(self,off=0):
		if not self.isValid(self.next_base):
			return 0
		value = api.rpm_uint16(self.pHandle,off+self.next_base)
		return value
		
	def read_uint32(self,off=0):
		if not self.isValid(self.next_base):
			return 0
		value = api.rpm_uint32(self.pHandle,off+self.next_base)
		return value
		
	def read_int32(self,off=0):
		if not self.isValid(self.next_base):
			return 0
		value = api.rpm_int32(self.pHandle,off+self.next_base)
		return value
		
	def read_uint64(self,off=0):
		if not self.isValid(self.next_base):
			return 0
		value = api.rpm_uint64(self.pHandle,off+self.next_base)
		
		return value
		
	def write_uint32(self,val,off=0):
		api.wpm_uint32(self.pHandle,off+self.next_base,val)
		
	def write_uint64(self,val,off=0):
		api.wpm_uint64(self.pHandle,off+self.next_base,val)
		
	def read_string(self,off):
		str = api.rpm_string(self.pHandle,off+self.next_base)
		return str
		
	def read_pstring(self,off):
		str = api.rpm_pstring(self.pHandle,off+self.next_base)
		return str
		
	def read_vec4(self,off=0):
		value = api.rpm_vec4(self.pHandle,off+self.next_base)
		return value
		
	def read_mat4(self,off=0):
		value = api.rpm_mat4(self.pHandle,off+self.next_base)
		return value
		
	def read_float(self,off=0):
		value = api.rpm_float(self.pHandle,off+self.next_base)
		return value


class memscan():
	def __init__(self,pHandle):
		for a in api.iter_region(pHandle):
			virtaddr = a[0]
			virtsize = a[1]
			data = bytearray(virtsize)
			datatype = (c_ubyte*virtsize)
			buf = datatype.from_buffer(data)
			api.ReadProcessMemory(pHandle,LPCVOID(virtaddr),buf,c_int(virtsize),None)
			data.find(b'\xff\xc0\x22\x90')
			del data
		
		
class sigscan():
	def __init__(self,pHandle):
	
		self._sections = []
		start = 0x140000000
		mem = MemAccess(pHandle)
		e_lfanew = mem[start].read_uint32(0x3C)
		NumberOfSections = mem[start+e_lfanew].read_uint16(0x6)
		SizeOfOptionalHeader = mem[start+e_lfanew].read_uint16(0x14)
		sectionarr = start+e_lfanew+0x18+SizeOfOptionalHeader

		for j in range(NumberOfSections):
			sec = sectionarr + j*0x28
			secname = ""
			for i in range(8):
				val = mem[sec].read_uint8(i)
				if (val==0): break
				secname += chr(val)
			virtsize = mem[sec].read_uint32(0x8)
			virtaddr = mem[sec].read_uint32(0xC)
			chars = mem[sec].read_uint32(0x24)
			data = bytearray(virtsize)
			datatype = (c_ubyte*virtsize)
			buf = datatype.from_buffer(data)
			api.ReadProcessMemory(pHandle,LPCVOID(start+virtaddr),buf,c_int(virtsize),None)
			self._sections += [[secname,start+virtaddr,virtsize,chars,data]]
				
	def scan(self,sig):
		sig = sig.split()
		q = []
		match = True
		keydone = False
		key = bytearray()
		for elem in sig:
			if ((elem == "?") or (elem == "??")):
				q += [None]
				keydone = True
			else:
				val = int(elem,16)
				q += [val]
				if not keydone: key.append(val)
		for sec in self._sections:
			data = sec[4]
			size = sec[2]
			ind = 0
			i = 0
			while (i!=-1):
				match = True
				i = data.find(key,ind)
				if (i==-1): 
					match = False
					break
				ind = i+1
				for j in range(len(q)):
					if q[j] == None:
						continue
					elif q[j] != data[i+j]:
						match = False
						break
				if (match):
					break
			if (match):
					break
		if (match):
			return sec[1] + i
		else:
			return -1
		
def get_codecave(pHandle):
	start = 0x140000000
	mem = MemAccess(pHandle)
	e_lfanew = mem[start].read_uint32(0x3C)
	NumberOfSections = mem[start+e_lfanew].read_uint16(0x6)
	SizeOfOptionalHeader = mem[start+e_lfanew].read_uint16(0x14)
	sectionarr = start+e_lfanew+0x18+SizeOfOptionalHeader
	
	codecaves=[]
	
	for j in range(NumberOfSections):
		sec = sectionarr + j*0x28
		secname = ""
		for i in range(8):
			val = mem[sec].read_uint8(i)
			if (val==0): break
			secname += chr(val)
		virtsize = mem[sec].read_uint32(0x8)
		virtaddr = mem[sec].read_uint32(0xC)
		chars = mem[sec].read_uint32(0x24)
		store = DWORD(chars)
		prot = DWORD()
		api.VirtualProtectEx(pHandle,LPVOID(start+virtaddr+(virtsize&0xfffff000)),c_int(0x1000),store,byref(prot))
		api.VirtualProtectEx(pHandle,LPVOID(start+virtaddr+(virtsize&0xfffff000)),c_int(0x1000),prot,None)

		if ((prot.value & 0x20) and (virtsize&0xFFF)):
			ccspace = 0x1000 - (virtsize & 0xFFF)
			if (ccspace >= 0x410):
				codecaves += [start+virtaddr+(virtsize&0xfffff000)+0x1000-0x400]
	return codecaves[-1]
	
	
def get_buildtime(pHandle):
	start = 0x140000000
	mem = MemAccess(pHandle)
	e_lfanew = mem[start].read_uint32(0x3C)
	timestamp = mem[start+e_lfanew].read_uint32(0x8)
	return timestamp

	
global api
api = WinApi()


def patch(pHandle,addr,bytes):
	PAGE_SIZE = 0x1000
	PAGE_FLR = 0xFFFFFFFFFFFFF000
	PAGE_RWX = 0x40
	protection = DWORD()
	api.VirtualProtectEx(pHandle,LPVOID(addr&PAGE_FLR),c_int(PAGE_SIZE),DWORD(PAGE_RWX),byref(protection))
	buff = (c_ubyte * len(bytes)).from_buffer_copy(bytes)
	api.WriteProcessMemory(pHandle,LPCVOID(addr),buff,c_int(len(bytes)),None)
	api.VirtualProtectEx(pHandle,LPVOID(addr&PAGE_FLR),c_int(PAGE_SIZE),protection,byref(protection))
	
	
ULONG_PTR = PVOID = LPVOID = PVOID64 = c_void_p
NTSTATUS = DWORD
KAFFINITY = ULONG_PTR
SDWORD = c_int32
ThreadBasicInformation = 0
STATUS_SUCCESS = 0

class CLIENT_ID(Structure):
	_fields_ = [
		("UniqueProcess",   PVOID),
		("UniqueThread",	PVOID),
	]

class THREAD_BASIC_INFORMATION(Structure):
	_fields_ = [
		("ExitStatus",	  NTSTATUS),
		("TebBaseAddress",  PVOID),	 # PTEB
		("ClientId",		CLIENT_ID),
		("AffinityMask",	KAFFINITY),
		("Priority",		SDWORD),
		("BasePriority",	SDWORD),
	]

windll.ntdll.NtQueryInformationThread.argtypes = [HANDLE, DWORD, POINTER(THREAD_BASIC_INFORMATION), ULONG, POINTER(ULONG)]
windll.ntdll.NtQueryInformationThread.restype = NTSTATUS


class StackAccess():
	def __init__(self,handle,threadid):
		self.buffer = b""
	
		self.phandle = handle
		mem = MemAccess(handle)
		#print("[+] Inspecting Thread ID: 0x%x"% (threadid))
		h_thread = windll.kernel32.OpenThread(0x001F03FF, None, threadid)
		self.h_thread = h_thread
		tbi = THREAD_BASIC_INFORMATION()
		len = c_ulonglong()
		result = windll.ntdll.NtQueryInformationThread(h_thread, ThreadBasicInformation, byref(tbi), sizeof(tbi), None)
		if result == STATUS_SUCCESS:
			teb_base = tbi.TebBaseAddress
			self.stack_start = mem[teb_base].read_uint32(0x8)
			self.stack_end = mem[teb_base].read_uint32(0x10)
			self.stack_size = self.stack_start - self.stack_end
			self.buffer = create_string_buffer(self.stack_size)
		
	def read(self):
		cbuff = (c_char * len(self.buffer)).from_buffer(self.buffer)
		
		val = api.ReadProcessMemory(self.phandle,c_ulonglong(self.stack_end),byref(cbuff),sizeof(self.buffer),None)
		if val == 0:
			return b""

		return self.buffer.raw
		
	def close(self):
		return windll.kernel32.CloseHandle(self.h_thread)
		
		
