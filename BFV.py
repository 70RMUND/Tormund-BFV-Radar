import MemAccess
import copy
import time
from MemAccess import *

# BFV Related Offsets
NDM_FRAMES = 0 #
NDM_BUSY = 4 #
NDM_LOCALPLAYER = 8 #
NDM_PLAYERLIST = 0x10 #
NDM_TYPEINFOLIST = 0x18 #
NDM_ENTITYKEYLIST = 0x20 #
ClientPlayer_TeamID = 0x1C48 #
ClientPlayer_Soldier = 0x1d50 #
ClientPlayer_Vehicle = 0x1d60 #
GameRenderer_RenderView = 0x60 #
RenderView_ViewMatrix = 0x2F0 #
HC_Health = 0x20
HC_MaxHealth = 0x24
CVE_TeamID = 0x234
CSE_HealthComponent = 0x2e8 # DONE
CCPE_Transform = 0x3a0#0x3c0
CSE_Player = 0x3A8
CVE_VehicleEntityData = 0x38
VED_ControllableType = 0x1F8
CCAT_ActiveTrigger = 0xD84
CCAT_TriggerData = 0x28
CCAT_ppAreaBounds = 0x60
VVSD_PointsArray = 0x20
AOD_ObjectiveArray = 0x18
OD_Transform = 0x30
OD_ShortName = 0x20
OD_LongName = 0x80
OD_TeamState = 0x88
OD_ControlledState = 0x8C

global offsets
offsets = {}

def isValid(addr):
	return ((addr >= 0x10000) and (addr < 0x0000001000000000))
	
def isValidInGame(addr):
	return ((addr >= 0x140000000) and (addr < 0x14FFFFFFF))
	
def numOfZeros(value):
	tmp = value
	ret = 0;
	for i in range(8):
		if (((tmp>>(i*8))&0xFF) == 0x00):
			ret += 1
	return ret

		
class PointerManager():
	def __init__(self,pHandle):
		self.mem = MemAccess(pHandle)
		self.pHandle = pHandle
		self.gpumemptr = 0
		self.OBFUS_MGR = 0
		if (offsets["OBFUS_MGR"] == 0):
			offsets["OBFUS_MGR"] = self.GetObfuscationMgr()
		else:
			self.OBFUS_MGR = offsets["OBFUS_MGR"]
		
	@staticmethod
	def decrypt_ptr(encptr, key):
		# Grab byte at location
		def GRAB_BYTE(x,n):
			return (x >> (n*8))&0xFF
		ret = 0
		subkey = (key^((5*key)%(2**64)))%(2**64)
		for i in range(7):
			y = GRAB_BYTE(subkey,i)
			subkey += 8
			t1 = (y*0x3B)%(2**8)
			t2 = (y + GRAB_BYTE(encptr,i)) % (2**8)
			ret |= (t2^t1)<<(i*8)
		ret |= GRAB_BYTE(encptr,7)<< 56
		ret &= 0x7FFFFFFFFFFFFFFF
		return ret
		
		
	def GetObfuscationMgr(self):
		api._cache_en = False
		print ("[+] Searching for ObfuscationMgr...")
		addr = -1
		OM = 0
		ss = StackAccess(self.pHandle,self.mem[offsets["PROTECTED_THREAD"]].read_uint32(0))
		while (1):
			addr = -1
			time.sleep(0.001)
			buf = ss.read()
			
			for i in range(0,len(buf),8):
				testptr = int.from_bytes(buf[i:i+8],"little")
				if (isValid(testptr)):
					if self.mem[testptr].read_uint64(0x0) == offsets["OBFUS_MGR_PTR_1"]:
						OM = testptr
						self.OBFUS_MGR = testptr
						break

			if (OM>0): break
		ss.close()
		print ("[+] Found ObfuscationMgr @ 0x%08x "%(OM))
		api._cache_en = True
		return OM
		
	def GetDx11Secret(self):
		def TestDx11Secret(self, testkey):
			mem = self.mem
			typeinfo = offsets["ClientStaticModelEntity"]
			
			flink = mem[typeinfo].read_uint64(0x88)

			ObfManager = self.OBFUS_MGR
			HashTableKey = mem[typeinfo](0).me() ^ mem[ObfManager].read_uint64(0xE0)
			
			hashtable = ObfManager+0x78
			EncryptionKey = self.hashtable_find(hashtable, HashTableKey)
			
			if (EncryptionKey == 0):
				return 0
				
			EncryptionKey ^= testkey
			ptr = PointerManager.decrypt_ptr(flink, EncryptionKey)

			if (isValid(ptr)):
				return True
			else:
				return False
			
			
		api._cache_en = False
		if (TestDx11Secret(self,offsets["Dx11Secret"])):
			api._cache_en = True
			return offsets["Dx11Secret"]
		
		if (offsets["GPUMemPtr"]):
			for offset in range(0,0x400,0x100):
				testptr = self.mem[offsets["GPUMemPtr"]].read_uint64(offset)
				if (testptr):
					if (TestDx11Secret(self,testptr)):
						if (testptr != offsets["Dx11Secret"]):
							print ("[+] Found Dx11 key scraping GPU mem @ 0x%x"%(offsets["GPUMemPtr"]+offset))
							offsets["Dx11Secret"] = testptr
							api._cache_en = True
							return offsets["Dx11Secret"]
			offsets["GPUMemPtr"] = 0
			
			
		ss = StackAccess(self.pHandle,self.mem[offsets["PROTECTED_THREAD"]].read_uint32(0))
		if (self.mem[self.OBFUS_MGR].read_uint64(0x100) != 0):
			addr = -1
			OM = 0
			i = 0
			print("[+] Locating initial Dx11 key location, please wait...")
			while (1):
				addr = -1
				buf = ss.read()
				addr = buf.find((offsets["OBFUS_MGR_RET_1"]).to_bytes(8, byteorder='little'))
				while (addr > -1):
					i = 0x38
					gpumem = int.from_bytes(buf[addr+i:addr+i+8],"little")
					testptr = self.mem[gpumem].read_uint64(0x0)
					if (TestDx11Secret(self,testptr)):
						if (testptr != offsets["Dx11Secret"]):
							offsets["GPUMemPtr"] = gpumem&0xFFFFFFFFFFFFFC00
							print ("[+] Found Initial Dx11 key scraping GPU mem @ 0x%x"%(offsets["GPUMemPtr"]))
							offsets["Dx11Secret"] = testptr
							api._cache_en = True
							ss.close()
							return offsets["Dx11Secret"]
					addr = buf.find((offsets["OBFUS_MGR_RET_1"]).to_bytes(8, byteorder='little'),addr+8)
		else:
			offsets["Dx11Secret"] = 0
			api._cache_en = True
			ss.close()
			return 0
			
	def CheckCryptMode(self):
		api._cache_en = False
		DecFunc = self.mem[self.OBFUS_MGR].read_uint64(0xE0) ^ self.mem[self.OBFUS_MGR].read_uint64(0xF8)
		Dx11EncBuffer = self.mem[self.OBFUS_MGR].read_uint64(0x100)
		
		if ((Dx11EncBuffer != 0) and (offsets["Dx11EncBuffer"] != Dx11EncBuffer)):
			self.GetDx11Secret()
			print ("[+] Dynamic key loaded, root key set to 0x%x"%(offsets["Dx11Secret"]))
			offsets["Dx11EncBuffer"] = Dx11EncBuffer
			offsets["CryptMode"] = 1
		elif (offsets["CryptMode"] == 0):
			if ((DecFunc == offsets["OBFUS_MGR_DEC_FUNC"]) and (Dx11EncBuffer != 0)):
				self.GetDx11Secret()
				print ("[+] Dynamic key loaded, retrieving key...")
				offsets["Dx11EncBuffer"] = Dx11EncBuffer
				offsets["CryptMode"] = 1
		elif (offsets["CryptMode"] == 1):
			if (DecFunc != offsets["OBFUS_MGR_DEC_FUNC"]):
				offsets["Dx11Secret"] = 0x598447EFD7A36912
				print ("[+] Static key loaded, root key set to 0x%x"%(offsets["Dx11Secret"]))
				offsets["CryptMode"] = 0
				self.gpumemptr = 0
		api._cache_en = True
		
	def hashtable_find(self, table, key):
		mem = self.mem
		bucketCount = mem[table].read_uint32(0x10)
		if (bucketCount == 0):
			return 0
		elemCount = mem[table].read_uint32(0x14)
		startcount = key % bucketCount
		node = mem[table](0x8)(0x8*startcount).me()
		
		if (node == 0):
			return 0
		
		while 1:
			first = mem[node].read_uint64(0x0)
			second = mem[node].read_uint64(0x8)
			next = mem[node].read_uint64(0x10)

			if first == key:
				#print ("Key: 0x%016x Node: 0x%016x"%(key^ mem[self.OBFUS_MGR].read_uint64(0xE0),node))
				return second       
			elif (next == 0):
				return 0
				
			node = next

	def GetLocalPlayer(self):
		self.CheckCryptMode()
		mem = self.mem
		ClientPlayerManager = mem[offsets["CLIENT_GAME_CONTEXT"]](0).read_uint64(0x60)
		ObfManager = self.OBFUS_MGR
		LocalPlayerListXorValue = mem[ClientPlayerManager].read_uint64(0xF8)
		LocalPlayerListKey = LocalPlayerListXorValue ^ mem[ObfManager].read_uint64(0xE0)
		
		hashtable = ObfManager+0x10
		EncryptedPlayerManager = self.hashtable_find(hashtable, LocalPlayerListKey)
		if (EncryptedPlayerManager == 0):
			return 0
		MaxPlayerCount = mem[EncryptedPlayerManager].read_uint32(0x18)
		
		if (MaxPlayerCount != 1):
			return 0
			
		XorValue1 = mem[EncryptedPlayerManager].read_uint64(0x20) ^ mem[EncryptedPlayerManager].read_uint64(0x8)
		XorValue2 = mem[EncryptedPlayerManager].read_uint64(0x10) ^ offsets["Dx11Secret"]
			
		LocalPlayer = mem[XorValue2].read_uint64(0) ^ XorValue1
		
		return LocalPlayer
		
	def GetPlayerById(self,id):
		self.CheckCryptMode()
		mem = self.mem
		ClientPlayerManager = mem[offsets["CLIENT_GAME_CONTEXT"]](0).read_uint64(0x60)
		ObfManager = self.OBFUS_MGR
		PlayerListXorValue = mem[ClientPlayerManager].read_uint64(0x100)
		PlayerListKey = PlayerListXorValue ^ mem[ObfManager].read_uint64(0xE0)
		
		hashtable = ObfManager+0x10
		EncryptedPlayerManager = self.hashtable_find(hashtable, PlayerListKey)
		if (EncryptedPlayerManager == 0):
			return 0
		MaxPlayerCount = mem[EncryptedPlayerManager].read_uint32(0x18)
		
		if (MaxPlayerCount != 70):
			return 0
			
		XorValue1 = mem[EncryptedPlayerManager].read_uint64(0x20) ^ mem[EncryptedPlayerManager].read_uint64(0x8)
		XorValue2 = mem[EncryptedPlayerManager].read_uint64(0x10) ^ offsets["Dx11Secret"]
		
		ClientPlayer = mem[XorValue2].read_uint64(0x8*id) ^ XorValue1
		
		return ClientPlayer
		
	def GetSpectatorById(self,id):
		self.CheckCryptMode()
		mem = self.mem
		ClientPlayerManager = mem[offsets["CLIENT_GAME_CONTEXT"]](0).read_uint64(0x60)
		ObfManager = self.OBFUS_MGR
		PlayerListXorValue = mem[ClientPlayerManager].read_uint64(0xF0)
		PlayerListKey = PlayerListXorValue ^ mem[ObfManager].read_uint64(0xE0)
		
		hashtable = ObfManager+0x10
		EncryptedPlayerManager = self.hashtable_find(hashtable, PlayerListKey)
		if (EncryptedPlayerManager == 0):
			return 0
		MaxPlayerCount = mem[EncryptedPlayerManager].read_uint32(0x18)

		if (MaxPlayerCount == 0) or (id >= MaxPlayerCount):
			return 0
			
		XorValue1 = mem[EncryptedPlayerManager].read_uint64(0x20) ^ mem[EncryptedPlayerManager].read_uint64(0x8)
		XorValue2 = mem[EncryptedPlayerManager].read_uint64(0x10) ^ offsets["Dx11Secret"]
		
		ClientPlayer = mem[XorValue2].read_uint64(0x8*id) ^ XorValue1
		
		return ClientPlayer
		
	def GetEntityKey(self,PointerKey):
		self.CheckCryptMode()
		mem = self.mem
		ObfManager = self.OBFUS_MGR
		HashTableKey = PointerKey ^ mem[ObfManager].read_uint64(0xE0)
		
		hashtable = ObfManager+0x78
		EncryptionKey = self.hashtable_find(hashtable, HashTableKey)
		
		if (EncryptionKey == 0):
			return 0

		EncryptionKey ^= offsets["Dx11Secret"]

		return EncryptionKey
		
	def DecryptPointer(self,EncPtr,PointerKey):
		self.CheckCryptMode()
		if not (EncPtr&0x8000000000000000):
			return 0
		mem = self.mem
		ObfManager = self.OBFUS_MGR
		HashTableKey = PointerKey ^ mem[ObfManager].read_uint64(0xE0)
		hashtable = ObfManager+0x78
		EncryptionKey = self.hashtable_find(hashtable, HashTableKey)
		
		if (EncryptionKey == 0):
			return 0
				
		EncryptionKey ^= offsets["Dx11Secret"]
		
		return PointerManager.decrypt_ptr(EncPtr,EncryptionKey)


def find_typeinfo(name,first,pHandle):
	mem = MemAccess(pHandle)
	typeinfo = first
	while (typeinfo):
		if mem[typeinfo](0).read_pstring(0) == name:
			return typeinfo
		typeinfo = mem[typeinfo].read_uint64(8)
	return -1
	

def build_offsets(pHandle):
	global offsets
	print ("[+] Gathering offsets, please wait...")
	x = sigscan(pHandle)
	mem = MemAccess(pHandle)
	offsets["OBFUS_MGR"] = 0;
	offsets["CryptMode"] = 0
	offsets["GPUMemPtr"] = 0
	offsets["Dx11Secret"] = 0x598447EFD7A36912
	offsets["Dx11EncBuffer"] = 0
	offsets["TIMESTAMP"] = get_buildtime(pHandle)
	
	offsets["GAMERENDERER"]                    = 0x1447f6fb8
	offsets["CLIENT_GAME_CONTEXT"]             = 0x1447522a8
	offsets["OBJECTIVE_MANAGER"]               = 0x14468B8B0 # FF 0D ? ? ? ? 48 8B 1D [? ? ? ?] 48 8B 43 10 48 8B 4B 08 48 3B C8 74 0E
	offsets["CLIENTSHRINKINGPLAYAREA"]         = 0x1446645A0 # ? 8B F2 48 8B D9 ? 8B 35 [? ? ? ?] ? 85 F6
	offsets["ClientSoldierEntity"]             = 0x144F2EF50
	offsets["ClientVehicleEntity"]             = 0x144E3A170
	offsets["ClientSupplySphereEntity"]        = 0x144C54550
	offsets["ClientCombatAreaTriggerEntity"]   = 0x144E3B870
	offsets["ClientExplosionPackEntity"]       = 0x144F346A0
	offsets["ClientProxyGrenadeEntity"]        = 0x144F34370
	offsets["ClientGrenadeEntity"]             = 0x144F34590
	offsets["ClientInteractableGrenadeEntity"] = 0x144C5BCB0
	offsets["ClientCapturePointEntity"]        = 0x144C8DD30
	offsets["ClientLootItemEntity"]            = 0x144C473A0
	offsets["ClientArmorVestLootItemEntity"]   = 0x144C89090
	offsets["ClientStaticModelEntity"]         = 0x144E32F10
	offsets["PROTECTED_THREAD"]                = 0x144752654
	offsets["OBFUS_MGR_PTR_1"]                 = 0x1438B46E0 
	offsets["OBFUS_MGR_RET_1"]                 = 0x147E2FEB6
	offsets["OBFUS_MGR_DEC_FUNC"]              = 0x14161F4C0
	offsets["OBJECTIVE_VTBL"]                  = 0x1437A7E68

	
	return offsets

def GetLocalPlayerList(pHandle):
	global offsets
	pm = PointerManager(pHandle)
	ind = 0
	plist = []
	
	for i in range(70):
		pPlayer = pm.GetPlayerById(i)
		if pPlayer != 0:
			plist += [pPlayer]
	
	return plist

def GetEncKey(pHandle,typeinfo):
	global offsets
	cache_en = api._cache_en
	api._cache_en = False
	global keystore
	mem = MemAccess(pHandle)
	pm = PointerManager(pHandle)
	
	if (mem[typeinfo].read_uint64(0x88) == 0):
		api._cache_en = cache_en
		return 0
	try:
		keystore
	except NameError:
		keystore = {}
	if typeinfo in keystore:
		api._cache_en = cache_en
		#print ("[+] Typeinfo: 0x%x Encryption Key: 0x%x"% (typeinfo,keystore[typeinfo]))
		return keystore[typeinfo]

	pm = PointerManager(pHandle)
	key = pm.GetEntityKey(mem[typeinfo](0).me())
	
	if key == 0:
		return 0
	
	keystore[typeinfo] = key
	
	api._cache_en = cache_en    
	print ("[+] Typeinfo: 0x%x Encryption Key: 0x%x"% (typeinfo,keystore[typeinfo]))
	return keystore[typeinfo]

def GetEntityList(pHandle,typeinfo,flink_offset=0x80):
	elist = []
	mem = MemAccess(pHandle)
	flink = mem[typeinfo].read_uint64(0x88)
	key = GetEncKey(pHandle,typeinfo)
	
	
	while (flink):
		ent = PointerManager.decrypt_ptr(flink,key)
		if ent >= 0x100000000000:
			return []
		elist += [ent-flink_offset]
		flink = mem[ent].read_uint64(0x0)
		
	return elist
	
def GetNextEntity(pHandle,Ptr,typeinfo,flink_offset=0x88):
	elist = []
	mem = MemAccess(pHandle)
	key = GetEncKey(pHandle,typeinfo)
	if Ptr == 0:
		flink = mem[typeinfo].read_uint64(0x88)
	else:
		flink = mem[Ptr].read_uint64(flink_offset)
		
	ptr = PointerManager.decrypt_ptr(flink,key)-flink_offset
	#if (typeinfo == offsets["ClientArmorVestLootItemEntity"]):
		#print (hex(ptr))
	if (isValid(ptr)):
		return ptr
	return 0

		
def GetHandle():
	def yes_or_no(question):
		while "the answer is invalid":
			reply = str(input(question+' (y/n): ')).lower().strip()
			if reply[:1] == 'y':
				return True
			if reply[:1] == 'n':
				return False
	pid = api.get_processid_by_name("bfv.exe")  
	if type(pid) == type(None):
		return 0
	pHandle = HANDLE(api.OpenProcess(DWORD(0x1f0fff),False,DWORD(pid)))
	priv = api.is_elevated(pHandle)
	if (priv == 2):
		ans = yes_or_no("[+] WARNING! BFV.exe is running as admin, do you still want to continue?")
		if (ans == False):
			exit(0)
	return pHandle.value
	
def GetEntityTransform(pHandle,Entity):
	mem = MemAccess(pHandle)
	flags = mem[Entity](0x40).read_uint64(0x8)
	if flags == None:
		return 0
	_9 = (flags>>8)&0xFF
	_10 = (flags>>16)&0xFF
	transform = mem[Entity](0x40).read_mat4((0x20*(_10+(2*_9)))+0x10)
	return transform
	
def list_current_entities(pHandle):
	global offsets
	mem = MemAccess(pHandle)
	next = offsets["FIRST_TYPEINFO"]
	while (next!=0):
		if (mem[next].read_uint64(0x68) &0x8000000000000000):
			str = mem[next](0).read_pstring(0)
			
			if len(str)>0:
				num = len(GetEntityList(pHandle,next))
				print("%d: %s" % (num,str))
		next = mem[next].read_uint64(0x8)

class GameSoldierData():
	name = ""
	pointer = 0
	transform = None
	health = 0
	maxhealth = 0
	teamid = 0
	alive = True
	vehicle = 0
	
class GameVehicleData():
	pointer = 0
	transform = None
	teamid = 0
	vehicletype = ""
	
class GameCapturePointData():
	pointer = 0
	transform = None
	objectivedata = None
	initialteamowner = 0
	radius = 0
	
class UIObjectiveData():
	pointer = 0
	transform = None
	shortname = ""
	longname = ""
	teamstate = 0
	controlledstate = 0
	capturepoint = None
	
class GameBoundsData():
	pointer = 0
	teamid = 0
	teamspecific = False
	points = []
	
class GameLootData():
	LootName = ""
	ItemName = ""
	LootType = 0
	VestEntity = False
	AccessCount = 0
	transform = [0,0,0,0]
	
class GameDebugPointData():
	chr = ""
	transform = [0,0,0,0]
	
class GameExplosiveData():
	pointer = 0
	teadid = 0
	transform = [0,0,0,0]

class GameGrenadeData():
	pointer = 0
	transform = [0,0,0,0]
	
class GameSupplyData():
	pointer = 0
	name = ""
	transform = [0,0,0,0]
	
class FSObjectData():
	pointer = 0
	typename = ""
	transform = [0,0,0,0]
	
class GameCircleData():
	pointer = 0
	OuterCircle_Moving = [0,0,0,0]
	InnerCircle_Const = [0,0,0,0]
	OuterCircleRadius_Moving = 0.0
	InnerCircleRadius_Const = 0.0
	
class GameCircleData():
	pointer = 0
	OuterCircle_Moving = [0,0,0,0]
	InnerCircle_Const = [0,0,0,0]
	OuterCircleRadius_Moving = 0.0
	InnerCircleRadius_Const = 0.0

class GameData():
	infirestorm = False
	testcrates = []
	testsafes = []
	myplayer = 0
	mysoldier = 0
	myteamid = 0
	myvehicle = 0
	myviewmatrix = 0
	mytransform = 0
	valid = False
	
	def __init__(self):
		self.soldiers = []
		self.vehicles = []
		self.capturepoints = []
		self.debugpoints = []
		self.loots = {}
		self.explosives = []
		self.grenades = []
		self.supplies = []
		self.fsobjects = []
		self.uiobjectives = []
		self.boundsdata = [[],[],[]]
		self.boundsstate = 0
		self.LastLootPtr = 0
		self.LastVestLootPtr = 0
		self.boundslimits = None# x low, x high, y low, y high
		self.circledata = None
		self.testpoint = False
	def AddSoldier(self,soldier):
		self.soldiers += [soldier]
	def ClearSoldiers(self):
		self.soldiers = []
	def AddVehicle(self,vehicle):
		self.vehicles += [vehicle]
	def ClearVehicles(self):
		self.vehicles = []
	def AddCapturePoint(self,capturepoint):
		self.capturepoints += [capturepoint]
	def ClearCapturePoints(self):
		self.capturepoints = []
	def AddUIObjective(self,uiobjective):
		self.uiobjectives += [uiobjective]
	def ClearUIObjectives(self):
		self.uiobjectives = []
	def AddDebugPoint(self,debugpoint):
		self.debugpoints += [debugpoint]
	def ClearDebugPoints(self):
		self.debugpoints = []
	def AddSupply(self,supply):
		self.supplies += [supply]
	def ClearSupplies(self):
		self.supplies = []
	def AddGrenade(self,grenade):
		self.grenades += [grenade]
	def ClearGrenades(self):
		self.grenades = []
	def AddExplosive(self,explosive):
		self.explosives += [explosive]
	def ClearExplosives(self):
		self.explosives = []
		
	def AddBoundsData(self,boundsdata, TeamID):
		for b in self.boundsdata[TeamID]:
			if b.pointer == boundsdata.pointer:
				return 0 
		self.boundsdata[TeamID] += [boundsdata]
		for p in boundsdata.points:
			if (self.boundslimits == None):
				self.boundslimits = [p[0],p[0],p[1],p[1]]
				continue
			if p[0] < self.boundslimits[0]:
				self.boundslimits[0] = p[0]
			if p[0] > self.boundslimits[1]:
				self.boundslimits[1] = p[0]
			if p[1] < self.boundslimits[2]:
				self.boundslimits[2] = p[1]
			if p[1] > self.boundslimits[3]:
				self.boundslimits[3] = p[1]
		return 1
	def ClearBoundsData(self):
		self.boundsdata[0] = [] # Neutral
		self.boundsdata[1] = [] # TeamID 1
		self.boundsdata[2] = [] # TeamID 2
		self.boundslimits = None


def DebugPrintMatrix(mat):
	print("[%.3f %.3f %.3f %.3f ]"  %(mat[0][0],mat[0][1],mat[0][2],mat[0][3]))
	print("[%.3f %.3f %.3f %.3f ]"  %(mat[1][0],mat[1][1],mat[1][2],mat[1][3]))
	print("[%.3f %.3f %.3f %.3f ]"  %(mat[2][0],mat[2][1],mat[2][2],mat[2][3]))
	print("[%.3f %.3f %.3f %.3f ]\n"%(mat[3][0],mat[3][1],mat[3][2],mat[3][3]))
	
def DebugPrintVec4(Vec4):
	print("[%.3f %.3f %.3f %.3f ]\n"  %(Vec4[0],Vec4[1],Vec4[2],Vec4[3]))
	
def MakeBoundsData(pHandle,VVSDAddr,Team,IsTeamSpecific):
	mem = MemAccess(pHandle)
	PointsList = mem[VVSDAddr](VVSD_PointsArray).me()
	PointsListSize = mem[PointsList-0x4].read_uint32()
	BoundsData = GameBoundsData()
	BoundsData.teamid = Team
	BoundsData.teamspecific = (False,True)[IsTeamSpecific]
	BoundsData.points = []
	BoundsData.pointer = VVSDAddr
	for i in range(PointsListSize):
		BoundsData.points += [mem[PointsList+(i*16)].read_vec4(0)]
	return BoundsData


def Process(pHandle,cnt):
	global offsets
	api._access=0
	#api._cache_en = True
	del api._cache
	api._cache = {}
	
	mem = MemAccess(pHandle)
	pm = PointerManager(pHandle)
	
	global g_gamedata
	try:
		g_gamedata
	except NameError:
		g_gamedata = GameData()

	def GetEntityVec4(pHandle,Entity):
		mem = MemAccess(pHandle)
		flags = mem[Entity](0x40).read_uint64(0x8)
		if flags == None:
			return 0
		_9 = (flags>>8)&0xFF
		_10 = (flags>>16)&0xFF
		_off = (0x20*(_10+(2*_9)))+0x10
		v4 = [mem[Entity](0x40).read_uint32(_off+0x30),
		mem[Entity](0x40).read_uint32(_off+0x34),
		mem[Entity](0x40).read_uint32(_off+0x38),
		mem[Entity](0x40).read_uint32(_off+0x40)]
		return v4
		
	
		
	# Get Local Info
	MyPlayer = pm.GetLocalPlayer()
	MySoldier = mem[MyPlayer].weakptr(ClientPlayer_Soldier).me()
	MyTeamId = mem[MyPlayer].read_uint32(ClientPlayer_TeamID)
	MyVehicle = mem[MyPlayer].weakptr(ClientPlayer_Vehicle).me()
	MyViewmatrix = mem[offsets["GAMERENDERER"]]()(GameRenderer_RenderView).read_mat4(RenderView_ViewMatrix)
	MyTransform = GetEntityTransform(pHandle,MySoldier)
	MyPos = GetEntityVec4(pHandle,MySoldier)
	g_gamedata.myplayer = MyPlayer
	g_gamedata.mysoldier = MySoldier
	g_gamedata.myteamid = MyTeamId
	g_gamedata.myvehicle = MyVehicle
	g_gamedata.myviewmatrix = MyViewmatrix
	g_gamedata.mytransform = MyTransform
	
	
	#print ("MyPlayer : 0x%016X" % MyPlayer)
	#print ("MySoldier: 0x%016X" % MySoldier)
	#print ("MyTeamId : 0x%016X" % MyTeamId)
	#print ("MyPos    : %s\n" % str(MyPos))
		
	if MySoldier == 0:
		g_gamedata.myviewmatrix = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
		g_gamedata.mytransform = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]

	g_gamedata.valid = True
	
	# Render Soldiers
	g_gamedata.ClearSoldiers()
	for Soldier in GetEntityList(pHandle,offsets["ClientSoldierEntity"],0xf0):
		#print ("0x%016x"%Soldier)
		
		# if you are me, skip
		if (Soldier == MySoldier):
			continue

		# if you are not attached to a ClientPlayer, skip
		if (mem[Soldier](CSE_Player).me() == 0):
			continue
		
		# if you are in my vehicle, skip
		Vehicle = mem[Soldier](CSE_Player).weakptr(ClientPlayer_Vehicle).me()
		if ((MyVehicle>0) and Vehicle == MyVehicle):
			continue
			
		TeamId = mem[Soldier](CSE_Player).read_uint32(ClientPlayer_TeamID)
		Transform = GetEntityTransform(pHandle,Soldier)
		
		
		if Transform == 0:
			continue
		
		Health = mem[Soldier](CSE_HealthComponent).read_float(HC_Health)
		MaxHealth = mem[Soldier](CSE_HealthComponent).read_float(HC_MaxHealth)
		
		name = mem[Soldier](CSE_Player).read_string(0x40)
		
		Alive = True
		if (Health <= 0.0):
			Alive = False

		SoldierData = GameSoldierData()
		SoldierData.teamid = TeamId
		SoldierData.transform = Transform
		SoldierData.alive = Alive
		SoldierData.vehicle = Vehicle
		SoldierData.pointer = Soldier
		SoldierData.health = Health
		SoldierData.maxhealth = MaxHealth
		SoldierData.name = name
		
		g_gamedata.AddSoldier(SoldierData)
	
	# Render Vehicles
	g_gamedata.ClearVehicles()
	for Vehicle in GetEntityList(pHandle,offsets["ClientVehicleEntity"],0xF0):
		if (Vehicle == MyVehicle):
			continue
		#print (hex(Vehicle))
		Transform = GetEntityTransform(pHandle,Vehicle)
		
		if Transform == 0:
			continue

		VehicleData = GameVehicleData()
		VehicleData.ownership = 0
		VehicleData.transform = Transform
		VehicleData.pointer = Vehicle
		VehicleData.vehicletype = mem[Vehicle](CVE_VehicleEntityData).read_pstring(VED_ControllableType)
		VehicleData.teamid = (mem[Vehicle].read_uint32(CVE_TeamID))
		g_gamedata.AddVehicle(VehicleData)
		#print ("0x%016x"%Vehicle)
	
	# Get all objectives by accessing ObjectiveManager and iterating all ObjectiveData
	g_gamedata.ClearUIObjectives()
	i=0
	while (1):
		UIObj = mem[offsets["OBJECTIVE_MANAGER"]](0)(0x38).read_uint64(i*8)
		i+=1
		if mem[UIObj].read_uint64(0) != offsets["OBJECTIVE_VTBL"]:
			break
		
		Transform = mem[UIObj].read_mat4(OD_Transform)
		ShortName = mem[UIObj].read_pstring(OD_ShortName)
		LongName = mem[UIObj].read_pstring(OD_LongName)
		TeamState = mem[UIObj].read_uint32(OD_TeamState)
		ControlledState = mem[UIObj].read_uint32(OD_ControlledState)
		
		UIObjective = UIObjectiveData() 
		UIObjective.pointer = UIObj
		UIObjective.transform = Transform
		UIObjective.shortname = ShortName
		UIObjective.longname = LongName
		UIObjective.teamstate = TeamState
		UIObjective.controlledstate = ControlledState
		g_gamedata.AddUIObjective(UIObjective)
		

			
			

	# Get the shape of the map bounds by iterating ClientCombatAreaTriggerEntity and reading bounds points
	ST_UPDATE = 0
	ST_UPDATENEXT = 1
	ST_SCAN = 2
	for ClientCombatAreaTrigger in GetEntityList(pHandle,offsets["ClientCombatAreaTriggerEntity"],0xD40):
		ActiveTrigger = mem[ClientCombatAreaTrigger].read_uint32(CCAT_ActiveTrigger)
		ClientCombatAreaTriggerData = mem[ClientCombatAreaTrigger](CCAT_TriggerData).me()
		Team = mem[ClientCombatAreaTriggerData].read_uint32(0x28)
		IsTeamSpecific = mem[ClientCombatAreaTriggerData].read_uint8(0x2D)
		updateShape = True
		
		ShapeData = mem[ClientCombatAreaTrigger](CCAT_ppAreaBounds)(0x0).me()

		if (g_gamedata.boundsstate == ST_SCAN):
			for Shape in g_gamedata.boundsdata[0]:
				if Shape.pointer == ShapeData:
					updateShape = False
			if (updateShape):
				g_gamedata.boundsstate = ST_UPDATENEXT
				
		if (g_gamedata.boundsstate == ST_UPDATE):
			g_gamedata.AddBoundsData(MakeBoundsData(pHandle,ShapeData,Team,IsTeamSpecific),0)
		
		i = 0xF0
		
		while (1):
			ShapeData = mem[ClientCombatAreaTrigger](i).me()
			if (ShapeData == 0): break
			
			if (g_gamedata.boundsstate == ST_SCAN):
				updateShape = True
				for Shape in g_gamedata.boundsdata[Team]:
					if Shape.pointer == ShapeData:
						updateShape = False
				if (updateShape and len(g_gamedata.boundsdata[Team])):
					g_gamedata.boundsstate = ST_UPDATENEXT
					break
			if (g_gamedata.boundsstate == ST_UPDATE):
				g_gamedata.AddBoundsData(MakeBoundsData(pHandle,ShapeData,Team,IsTeamSpecific),Team)
			else:
				break
			i+= 0x60
	if (g_gamedata.boundsstate == ST_UPDATENEXT):
		g_gamedata.boundsstate = ST_UPDATE
		g_gamedata.ClearBoundsData()
	elif (g_gamedata.boundsstate == ST_UPDATE):
		g_gamedata.boundsstate = ST_SCAN
	
	g_gamedata.ClearExplosives()
	for Explosive in GetEntityList(pHandle,offsets["ClientExplosionPackEntity"],0xf0):
		#print ("Explosive: " + hex(Explosive))
		Transform = GetEntityTransform(pHandle,Explosive)
		Team = mem[Explosive].read_uint32(0x4c0)
		ExplosiveData = GameExplosiveData()
		ExplosiveData.transform = Transform
		ExplosiveData.teamid = Team
		ExplosiveData.pointer = Explosive
		g_gamedata.AddExplosive(ExplosiveData)

	g_gamedata.ClearGrenades()
	for Grenade in (GetEntityList(pHandle,offsets["ClientProxyGrenadeEntity"],0xf0)+GetEntityList(pHandle,offsets["ClientGrenadeEntity"],0xf0)+GetEntityList(pHandle,offsets["ClientInteractableGrenadeEntity"],0xf0)):
		Transform = GetEntityTransform(pHandle,Grenade)
		GrenadeData = GameGrenadeData()
		GrenadeData.transform = Transform
		GrenadeData.pointer = Grenade
		g_gamedata.AddGrenade(GrenadeData)
		
	g_gamedata.ClearSupplies()
	for Supply in GetEntityList(pHandle,offsets["ClientSupplySphereEntity"],0xb8):
		#print (hex(Supply))
		SupplyName = mem[Supply](0x38).read_pstring(0xB8)
		pos = mem[Supply].read_vec4(0x100)
		#if pos == 0:
		#   continue
		
		#print ("0x%x (%s)"% (Supply,SupplyName))
		#print("%f %f %f %f"%(pos[0],pos[1],pos[2],pos[3]))
		#print("%f %f %f %f"%(MyTransform[1][0],MyTransform[1][1],MyTransform[1][2],MyTransform[1][3]))
		#print("%f %f %f %f"%(MyTransform[2][0],MyTransform[2][1],MyTransform[2][2],MyTransform[2][3]))
		#print("%f %f %f %f"%(MyTransform[3][0],MyTransform[3][1],MyTransform[3][2],MyTransform[3][3]))
		
		
		SupplyData = GameSupplyData()
		SupplyData.transform = [[0,0,0,0],[0,0,0,0],[0,0,0,0],pos]
		SupplyData.name = SupplyName
		SupplyData.pointer = Supply
		g_gamedata.AddSupply(SupplyData)
		
		

	# This pointer only exists if we are in FireStorm mode
	ShrinkingPlayArea = mem[offsets["CLIENTSHRINKINGPLAYAREA"]](0).me()
	g_gamedata.circledata = None
	if (not ShrinkingPlayArea):
		g_gamedata.infirestorm = False
		g_gamedata.fsobjects = []
		
	if (ShrinkingPlayArea):
		if (not g_gamedata.infirestorm):
			for model in GetEntityList(pHandle,offsets["ClientStaticModelEntity"],0xf0):
				name = mem[model](0x38)(0xA8).read_pstring(0x18)
				if name == "artassets/props/gadgetcrate_01/gadgetcrate_01_200_paperfilling_Mesh":
					fsobject = FSObjectData()
					fsobject.pointer = model
					fsobject.typename = "crate"
					fsobject.transform = GetEntityTransform(pHandle,model)
					g_gamedata.fsobjects += [fsobject]
				elif name == "dakar/gameplay/prefabs/objectives/dk_safe_02_lid_Mesh":
					fsobject = FSObjectData()
					fsobject.pointer = model
					fsobject.typename = "safe"
					fsobject.transform = GetEntityTransform(pHandle,model)
					g_gamedata.fsobjects += [fsobject]
		g_gamedata.infirestorm = True
	
		
	
	
		CircleData = GameCircleData()
		CircleData.OuterCircle_Moving = mem[ShrinkingPlayArea].read_vec4(0x40)
		CircleData.InnerCircle_Const = mem[ShrinkingPlayArea].read_vec4(0x50)
		CircleData.OuterCircleRadius_Moving = mem[ShrinkingPlayArea].read_float(0x64)
		CircleData.InnerCircleRadius_Const = mem[ShrinkingPlayArea].read_float(0x68)
		g_gamedata.circledata = CircleData
		
		# So because python is slow and there are a lot of lootentities
		# lets just walk them 5 entities per render so we don't completely
		# kill our fps. We don't need low latency for these
		for n in range(5):
			g_gamedata.LastLootPtr = GetNextEntity(pHandle,g_gamedata.LastLootPtr,offsets["ClientLootItemEntity"],flink_offset=0xf0)
			if (g_gamedata.LastLootPtr!=0):
				if g_gamedata.LastLootPtr not in g_gamedata.loots:
					if (mem[g_gamedata.LastLootPtr].read_int32(0x238) != -1):
						Loot = GameLootData()
						Loot.LootName = mem[g_gamedata.LastLootPtr](0x720).read_pstring(0x40)
						Loot.LootType = mem[g_gamedata.LastLootPtr](0x38).read_uint32(0x118)
						Loot.ItemName = mem[g_gamedata.LastLootPtr](0x38)(0x100)(0x0).read_pstring(0x18)
						
						Loot.transform = GetEntityTransform(pHandle,g_gamedata.LastLootPtr)
						g_gamedata.loots[g_gamedata.LastLootPtr] = Loot
				else:
					g_gamedata.loots[g_gamedata.LastLootPtr].AccessCount += 1
					if (mem[g_gamedata.LastLootPtr].read_int32(0x238) == -1):
						del g_gamedata.loots[g_gamedata.LastLootPtr]
					elif (g_gamedata.loots[g_gamedata.LastLootPtr].AccessCount >= 50):
						loots = copy.copy(g_gamedata.loots)
						for LootPtr in loots:
							if g_gamedata.loots[LootPtr].AccessCount < 10:
								del g_gamedata.loots[LootPtr]
							else:
							   g_gamedata.loots[LootPtr].AccessCount = 0
				
		# So because python is slow and there are a lot of lootentities
		# lets just walk them 5 entities per render so we don't completely
		# kill our fps. We don't need low latency for these     
		for n in range(5):
			g_gamedata.LastVestLootPtr = GetNextEntity(pHandle,g_gamedata.LastVestLootPtr,offsets["ClientArmorVestLootItemEntity"],flink_offset=0xf0)
			
			if (g_gamedata.LastVestLootPtr!=0):
				
				if g_gamedata.LastVestLootPtr not in g_gamedata.loots:
					if (mem[g_gamedata.LastVestLootPtr].read_int32(0x238) != -1):
						Loot = GameLootData()
						Loot.LootName =  mem[g_gamedata.LastVestLootPtr](0x720).read_pstring(0x40)
						
						Loot.VestEntity = True
						Loot.ItemName = mem[g_gamedata.LastVestLootPtr](0x38)(0x100)(0x0).read_pstring(0x18)
						Loot.transform = GetEntityTransform(pHandle,g_gamedata.LastVestLootPtr)
						g_gamedata.loots[g_gamedata.LastVestLootPtr] = Loot
				else:
					g_gamedata.loots[g_gamedata.LastVestLootPtr].AccessCount += 1
					if (mem[g_gamedata.LastVestLootPtr].read_int32(0x238) == -1):
						del g_gamedata.loots[g_gamedata.LastVestLootPtr]






def initialize(pHandle):
	global offsets
	PAGE_SIZE = 0x1000
	ALL_ACCESS = 0x1f0fff
	PAGE_FLR = 0xFFFFFFFFFFFFF000
	PAGE_RWX = 0x40
	offsets = build_offsets(pHandle)
	return 
