import MemAccess
import copy
from MemAccess import *

# BFV Related Offsets
NDM_FRAMES = 0 #
NDM_BUSY = 4 #
NDM_LOCALPLAYER = 8 #
NDM_PLAYERLIST = 0x10 #
NDM_TYPEINFOLIST = 0x18 #
NDM_ENTITYKEYLIST = 0x20 #
ClientPlayer_TeamID = 0x1C48 #
ClientPlayer_Soldier = 0x1d48 #
ClientPlayer_Vehicle = 0x1d58 #
GameRenderer_RenderView = 0x60 #
RenderView_ViewMatrix = 0x2F0 #
HC_Health = 0x20
HC_MaxHealth = 0x24
CVE_TeamID = 0x1c4
CSE_HealthComponent = 0x278 #
CCPE_Transform = 0x3c0
CSE_TeamId = 0x1C48
CSE_Player = 0x308
CVE_VehicleEntityData = 0x30
VED_ControllableType = 0x1E8
CCAT_ActiveTrigger = 0xD7C
CCAT_TriggerData = 0x28
CCAT_ppAreaBounds = 0x60
VVSD_PointsArray = 0x18
OM_UIAllObjectivesData = 0x58
AOD_ObjectiveArray = 0x10
OD_Transform = 0x20
OD_ShortName = 0x18
OD_LongName = 0x70
OD_TeamState = 0x78
OD_ControlledState = 0x7C

global offsets
offsets = {}

def find_typeinfo(name,first,pHandle):
	mem = MemAccess(pHandle)
	typeinfo = mem[first].read_uint64(0)
	while (typeinfo):
		if mem[typeinfo](0).read_string(0) == name:
			return typeinfo
		typeinfo = mem[typeinfo].read_uint64(8)
	return -1
	

def build_offsets(pHandle):
	global offsets
	print ("[+] Gathering offsets, please wait...")
	x = sigscan(pHandle)
	mem = MemAccess(pHandle)
	offsets["TIMESTAMP"] = get_buildtime(pHandle)
	offsets["CODECAVE_ADDR"] = get_codecave(pHandle)
	offsets["NODICE_MGR"] = offsets["CODECAVE_ADDR"] - 0x8
	addr = x.scan("0F 84 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 3B 05 ?? ?? ?? ??")
	offsets["GAME_GET_CURRENT_THREAD_ID"] = mem[addr].read_int32(8)+addr+8+4
	offsets["GAME_APPROVED_THREAD"] = mem[addr].read_int32(14)+addr+14+4
	offsets["ORIGINAL_GTID_FUNC"] = offsets["CODECAVE_ADDR"] - 0x10
	addr = x.scan("E8 ? ? ? ? 48 8B F8 48 89 45 B8 84 DB")
	offsets["GET_LOCAL_PLAYER_FUNC"] = mem[addr].read_int32(1)+addr+1+4
	addr = x.scan("E8 ? ? ? ? 0F B6 D8 88 45 67 48 8D 4D C7")
	jfunc = mem[addr].read_uint32(1)+addr+1+4
	offsets["THREAD_CONTROL_FUNC"] = mem[jfunc].read_int32(1)+jfunc+1+4
	addr = x.scan("48 8B 05 ? ? ? ? 48 85 C0 74 26 4C 8B 40 40")
	offsets["CLIENT_GAME_CONTEXT"] = mem[addr].read_int32(3)+addr+3+4
	addr = x.scan("E8 ? ? ? ? 48 8B F0 48 8D 54 24 ? 48 8B 4B 28")
	offsets["GET_PLAYER_BY_INDEX_FUNC"] = mem[addr].read_int32(1)+addr+1+4
	addr = x.scan("48 85 D2 48 0F 45 CA 48 FF 25 ? ? ? ?")
	offsets["GAME_MALLOC"] = mem[addr].read_int32(10)+addr+10+4
	addr = x.scan("48 8B 53 08 48 8B 0B FF 15 ? ? ? ? 48 8B 5C 24")
	offsets["GAME_VIRTUALPROTECT"] = mem[addr].read_int32(9)+addr+9+4
	addr = x.scan("48 8B 0D ? ? ? ? 33 D2 48 8B 19")
	offsets["DX11RENDERER"] = mem[addr].read_int32(3)+addr+3+4
	addr = x.scan("E8 ? ? ? ? 48 8B D8 48 85 C0 0F 84 ? ? ? ? F3 0F 10 75 ?")
	offsets["GET_ENTITY_DATA"] = mem[addr].read_int32(1)+addr+1+4
	addr = x.scan("48 8B 0D ? ? ? ? 48 8B 01 B2 01 FF 50")
	offsets["GAMERENDERER"] = mem[addr].read_int32(3)+addr+3+4
	addr = x.scan("48 8B 05 ?? ?? ?? ?? 31 D2 48 85 C0 74")
	offsets["FIRST_TYPEINFO"] = mem[addr].read_int32(3)+addr+3+4
	addr = x.scan("FF 0D ?? ?? ?? ?? 48 89 CA 48 8B 1D ?? ?? ?? ??")
	offsets["OBJECTIVE_MANAGER"] = mem[addr].read_int32(12)+addr+12+4
	addr = x.scan("4C 8B F2 48 8B D9 48 8B 35 ? ? ? ? 48 85 F6")
	offsets["CLIENTSHRINKINGPLAYAREA"] = mem[addr].read_int32(9)+addr+9+4
	addr = find_typeinfo("ClientSoldierEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientSoldierEntity"] = addr
	addr = find_typeinfo("ClientVehicleEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientVehicleEntity"] = addr
	addr = find_typeinfo("ClientSupplySphereEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientSupplySphereEntity"] = addr
	addr = find_typeinfo("ClientCombatAreaTriggerEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientCombatAreaTriggerEntity"] = addr  
	addr = find_typeinfo("ClientExplosionPackEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientExplosionPackEntity"] = addr
	addr = find_typeinfo("ClientProxyGrenadeEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientProxyGrenadeEntity"] = addr
	addr = find_typeinfo("ClientGrenadeEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientGrenadeEntity"] = addr
	addr = find_typeinfo("ClientInteractableGrenadeEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientInteractableGrenadeEntity"] = addr 
	addr = find_typeinfo("ClientCapturePointEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientCapturePointEntity"] = addr
	addr = find_typeinfo("ClientLootItemEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientLootItemEntity"] = addr
	addr = find_typeinfo("ClientArmorVestLootItemEntity",offsets["FIRST_TYPEINFO"],pHandle)
	offsets["ClientArmorVestLootItemEntity"] = addr
	print ("[+] Done")
	return offsets

# Grab byte at location
def GRAB_BYTE(x,n):
	return (x >> (n*8))&0xFF
 
# Decrypt using subkey
def decrypt_ptr(encptr, key):
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
	
def GetLocalPlayerList(pHandle):
	global offsets
	mem = MemAccess(pHandle)
	ind = 0
	plist = []
	while (1):
		player = mem[offsets["NODICE_MGR"]](0)(NDM_PLAYERLIST).read_uint64(ind*8)
		if player == 0:
			break
		plist += [player]
		ind+=1
	return plist

def GetEncKey(pHandle,typeinfo):
	global offsets
	cache_en = api._cache_en
	api._cache_en = False
	global keystore
	mem = MemAccess(pHandle)
	if (mem[typeinfo].read_uint64(0x68) == 0):
		api._cache_en = cache_en
		return 0
	try:
		keystore
	except NameError:
		keystore = {}
	if typeinfo in keystore:
		api._cache_en = cache_en
		return keystore[typeinfo]
	
	mem[offsets["NODICE_MGR"]](0)(NDM_TYPEINFOLIST).write_uint64(0x0,0x0)
	mem[offsets["NODICE_MGR"]](0)(NDM_ENTITYKEYLIST).write_uint64(0x0,0x0)
	while (mem[offsets["NODICE_MGR"]](0)(NDM_ENTITYKEYLIST).read_uint64(0x0) != 0):
		pass
	mem[offsets["NODICE_MGR"]](0)(NDM_TYPEINFOLIST).write_uint64(typeinfo,0x0)
	while (mem[offsets["NODICE_MGR"]](0)(NDM_ENTITYKEYLIST).read_uint64(0x0) == 0):
		pass
	keystore[typeinfo] = mem[offsets["NODICE_MGR"]](0)(NDM_ENTITYKEYLIST).read_uint64(0x0)
	api._cache_en = cache_en
	return keystore[typeinfo]
	
def isValid(addr):
	return ((addr >= 0x10000) and (addr < 0x0000001000000000))

def GetEntityList(pHandle,typeinfo,flink_offset=0x80):
	elist = []
	mem = MemAccess(pHandle)
	flink = mem[typeinfo].read_uint64(0x68)
	key = GetEncKey(pHandle,typeinfo)
	
	while (flink):
		ent = decrypt_ptr(flink,key)
		elist += [ent-flink_offset]
		flink = mem[ent].read_uint64(0x0)
		
	return elist
	
def GetNextEntity(pHandle,Ptr,typeinfo,flink_offset=0x80):
	elist = []
	mem = MemAccess(pHandle)
	key = GetEncKey(pHandle,typeinfo)
	if Ptr == 0:
		flink = mem[typeinfo].read_uint64(0x68)
	else:
		flink = mem[Ptr].read_uint64(flink_offset)
		
	ptr = decrypt_ptr(flink,key)-flink_offset
	if (isValid(ptr)):
		return ptr
	return 0

		
def GetHandle():
	pid = api.get_processid_by_name("bfv.exe")
	if type(pid) == type(None):
		return 0
	pHandle = HANDLE(api.OpenProcess(DWORD(0x1f0fff),False,DWORD(pid)))
	return pHandle.value
	
def GetEntityTransform(pHandle,Entity):
	mem = MemAccess(pHandle)
	flags = mem[Entity](0x38).read_uint64(0x8)
	if flags == None:
		return 0
	_9 = (flags>>8)&0xFF
	_10 = (flags>>16)&0xFF
	transform = mem[Entity](0x38).read_mat4((0x20*(_10+(2*_9)))+0x10)
	return transform
	
def list_current_entities(pHandle):
	global offsets
	mem = MemAccess(pHandle)
	next = offsets["FIRST_TYPEINFO"]
	while (next!=0):
		if (mem[next].read_uint64(0x68) &0x8000000000000000):
			str = mem[next](0).read_string(0)
			
			if len(str)>0:
				num = len(GetEntityList(pHandle,next))
				print("%d: %s" % (num,str))
		next = mem[next].read_uint64(0x8)

class GameSoldierData():
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
	
class GameCircleData():
	pointer = 0
	OuterCircle_Moving = [0,0,0,0]
	InnerCircle_Const = [0,0,0,0]
	OuterCircleRadius_Moving = 0.0
	InnerCircleRadius_Const = 0.0

class GameData():
	myplayer = 0
	mysoldier = 0
	myteamid = 0
	myvehicle = 0
	myviewmatrix = 0
	mytransform = 0
	valid = False
	keydown = False
	
	def __init__(self):
		self.soldiers = []
		self.vehicles = []
		self.capturepoints = []
		self.debugpoints = []
		self.loots = {}
		self.explosives = []
		self.grenades = []
		self.supplies = []
		self.uiobjectives = []
		self.boundsdata = [[],[],[]]
		self.boundsstate = 0
		self.LastLootPtr = 0
		self.LastVestLootPtr = 0
		self.boundslimits = None# x low, x high, y low, y high
		self.keydown == False
		self.circledata = None
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
	
	global g_gamedata
	try:
		g_gamedata
	except NameError:
		g_gamedata = GameData()

	
	# Get Local Info
	MyPlayer = mem[offsets["NODICE_MGR"]]()(NDM_LOCALPLAYER).me()
	MySoldier = mem[MyPlayer].weakptr(ClientPlayer_Soldier).me()
	MyTeamId = mem[MyPlayer].read_uint32(ClientPlayer_TeamID)
	MyVehicle = mem[MyPlayer].weakptr(ClientPlayer_Vehicle).me()
	MyViewmatrix = mem[offsets["GAMERENDERER"]]()(GameRenderer_RenderView).read_mat4(RenderView_ViewMatrix)
	MyTransform = GetEntityTransform(pHandle,MySoldier)

	g_gamedata.myplayer = MyPlayer
	g_gamedata.mysoldier = MySoldier
	g_gamedata.myteamid = MyTeamId
	g_gamedata.myvehicle = MyVehicle
	g_gamedata.myviewmatrix = MyViewmatrix
	g_gamedata.mytransform = MyTransform
	
	if MySoldier == 0:
		g_gamedata.myviewmatrix = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
		g_gamedata.mytransform = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]

	g_gamedata.valid = True
	
	# Render Soldiers
	g_gamedata.ClearSoldiers()
	for Soldier in GetEntityList(pHandle,offsets["ClientSoldierEntity"],0x80):

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
			
		TeamId = mem[Soldier](CSE_Player).read_uint32(CSE_TeamId)
		Transform = GetEntityTransform(pHandle,Soldier)
		if Transform == 0:
			continue
		
		Health = mem[Soldier](CSE_HealthComponent).read_float(HC_Health)
		MaxHealth = mem[Soldier](CSE_HealthComponent).read_float(HC_MaxHealth)
		
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
		
		g_gamedata.AddSoldier(SoldierData)
	
	# Render Vehicles
	g_gamedata.ClearVehicles()
	for Vehicle in GetEntityList(pHandle,offsets["ClientVehicleEntity"],0x80):
		if (Vehicle == MyVehicle):
			continue
		Transform = GetEntityTransform(pHandle,Vehicle)
		if Transform == 0:
			continue
		
		VehicleData = GameVehicleData()
		VehicleData.ownership = 0
		VehicleData.transform = Transform
		VehicleData.pointer = Vehicle
		VehicleData.vehicletype = mem[Vehicle](CVE_VehicleEntityData).read_string(VED_ControllableType)
		VehicleData.teamid = mem[Vehicle].read_uint32(CVE_TeamID)
		
		g_gamedata.AddVehicle(VehicleData)
	
	# Get all objectives by accessing ObjectiveManager and iterating all ObjectiveData
	g_gamedata.ClearUIObjectives()
	UIObjArray = mem[offsets["OBJECTIVE_MANAGER"]](0x0)(OM_UIAllObjectivesData).read_uint64(AOD_ObjectiveArray)
	if (UIObjArray):
		size = mem[UIObjArray-0x4].read_uint32(0)
		for i in range(size):
			UIObj = mem[UIObjArray+(i*8)](0).me()
			Transform = mem[UIObj].read_mat4(OD_Transform)
			ShortName = mem[UIObj].read_string(OD_ShortName)
			LongName = mem[UIObj].read_string(OD_LongName)
			TeamState = mem[UIObj].read_uint32(OD_TeamState)
			ControlledState = mem[UIObj].read_uint32(OD_ControlledState)
			
			UIObjective = UIObjectiveData()	
			UIObjective.pointer = UIObj
			UIObjective.transform = Transform
			UIObjective.shortname = ShortName
			UIObjective.longname = LongName
			UIObjective.teamstate = TeamState
			UIObjective.controlledstate = ControlledState
			
			for CapturePoint in g_gamedata.capturepoints:
				if ((CapturePoint.transform[3][0] == Transform[3][0]) and
					(CapturePoint.transform[3][2] == Transform[3][2])):
					CapturePoint.objectivedata = UIObjective
					UIObjective.capturepoint = CapturePoint
			
			g_gamedata.AddUIObjective(UIObjective)

	# Get the shape of the map bounds by iterating ClientCombatAreaTriggerEntity and reading bounds points
	ST_UPDATE = 0
	ST_UPDATENEXT = 1
	ST_SCAN = 2
	for ClientCombatAreaTrigger in GetEntityList(pHandle,offsets["ClientCombatAreaTriggerEntity"],0xD40):
		ActiveTrigger = mem[ClientCombatAreaTrigger].read_uint32(CCAT_ActiveTrigger)
		ClientCombatAreaTriggerData = mem[ClientCombatAreaTrigger](CCAT_TriggerData).me()
		Team = mem[ClientCombatAreaTriggerData].read_uint32(0x20)
		IsTeamSpecific = mem[ClientCombatAreaTriggerData].read_uint8(0x25)
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
	for Explosive in GetEntityList(pHandle,offsets["ClientExplosionPackEntity"],0x80):
		Transform = GetEntityTransform(pHandle,Explosive)
		Team = mem[Explosive].read_uint32(0x4c0)
		ExplosiveData = GameExplosiveData()
		ExplosiveData.transform = Transform
		ExplosiveData.teamid = Team
		ExplosiveData.pointer = Explosive
		g_gamedata.AddExplosive(ExplosiveData)

	g_gamedata.ClearGrenades()
	for Grenade in (GetEntityList(pHandle,offsets["ClientProxyGrenadeEntity"],0x80)+GetEntityList(pHandle,offsets["ClientGrenadeEntity"],0x80)+GetEntityList(pHandle,offsets["ClientInteractableGrenadeEntity"],0x80)):
		Transform = GetEntityTransform(pHandle,Grenade)
		GrenadeData = GameGrenadeData()
		GrenadeData.transform = Transform
		GrenadeData.pointer = Grenade
		g_gamedata.AddGrenade(GrenadeData)
		
	g_gamedata.ClearSupplies()
	for Supply in GetEntityList(pHandle,offsets["ClientSupplySphereEntity"],0xa8):
		SupplyName = mem[Supply](0x30).read_string(0xB8)
		pos = mem[Supply].read_vec4(0xE0)
		SupplyData = GameSupplyData()
		SupplyData.transform = [[0,0,0,0],[0,0,0,0],[0,0,0,0],pos]
		SupplyData.name = SupplyName
		SupplyData.pointer = Supply
		g_gamedata.AddSupply(SupplyData)
		
	# This pointer only exists if we are in FireStorm mode
	ShrinkingPlayArea = mem[offsets["CLIENTSHRINKINGPLAYAREA"]](0).me()
	g_gamedata.circledata = None
	if (ShrinkingPlayArea):
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
			g_gamedata.LastLootPtr = GetNextEntity(pHandle,g_gamedata.LastLootPtr,offsets["ClientLootItemEntity"],flink_offset=0x80)
			if (g_gamedata.LastLootPtr!=0):
				if g_gamedata.LastLootPtr not in g_gamedata.loots:
					if (mem[g_gamedata.LastLootPtr].read_int32(0x1B8) != -1):
						Loot = GameLootData()
						Loot.LootName = mem[g_gamedata.LastLootPtr].read_string(0x5F0)
						Loot.LootType = mem[g_gamedata.LastLootPtr](0x30).read_uint32(0x108)
						Loot.ItemName = mem[g_gamedata.LastLootPtr](0x780)(0x8).read_string(0x180)
						if (Loot.LootName[-5:] != "Tier1"):
							Loot.transform = GetEntityTransform(pHandle,g_gamedata.LastLootPtr)
							g_gamedata.loots[g_gamedata.LastLootPtr] = Loot
				else:
					g_gamedata.loots[g_gamedata.LastLootPtr].AccessCount += 1
					if (mem[g_gamedata.LastLootPtr].read_int32(0x1B8) == -1):
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
			g_gamedata.LastVestLootPtr = GetNextEntity(pHandle,g_gamedata.LastVestLootPtr,offsets["ClientArmorVestLootItemEntity"],flink_offset=0x80)
			if (g_gamedata.LastVestLootPtr!=0):
				if g_gamedata.LastVestLootPtr not in g_gamedata.loots:
					if (mem[g_gamedata.LastVestLootPtr].read_int32(0x1B8) != -1):
						Loot = GameLootData()
						Loot.LootName = mem[g_gamedata.LastVestLootPtr].read_string(0x5F0)
						Loot.VestEntity = True
						Loot.ItemName = mem[g_gamedata.LastVestLootPtr](0x780)(0x8).read_string(0x180)
						if (Loot.LootName[-5:] != "Tier1"):
							Loot.transform = GetEntityTransform(pHandle,g_gamedata.LastVestLootPtr)
							g_gamedata.loots[g_gamedata.LastVestLootPtr] = Loot
				else:
					g_gamedata.loots[g_gamedata.LastVestLootPtr].AccessCount += 1
					if (mem[g_gamedata.LastVestLootPtr].read_int32(0x1B8) == -1):
						del g_gamedata.loots[g_gamedata.LastVestLootPtr]

def initialize(pHandle):
	global offsets
	PAGE_SIZE = 0x1000
	ALL_ACCESS = 0x1f0fff
	PAGE_FLR = 0xFFFFFFFFFFFFF000
	PAGE_RWX = 0x40
	offsets = build_offsets(pHandle)
	
	shellcode  = b"\x48\x81\xEC\xC8\x00\x00\x00\x48\xB8\xF0\x41\xEC\x42\x01\x00\x00"
	shellcode += b"\x00\xFF\x10\x89\x44\x24\x38\x48\xB8\x88\x52\x4B\x44\x01\x00\x00"
	shellcode += b"\x00\x8B\x4C\x24\x38\x39\x08\x74\x09\x8B\x44\x24\x38\xE9\x7F\x03"
	shellcode += b"\x00\x00\x48\xB8\x90\xF2\x63\x41\x01\x00\x00\x00\x48\x89\x84\x24"
	shellcode += b"\x80\x00\x00\x00\x48\xB8\x40\xD8\xB3\x47\x01\x00\x00\x00\x48\x89"
	shellcode += b"\x44\x24\x68\x48\xB8\x90\x00\x64\x41\x01\x00\x00\x00\x48\x89\x84"
	shellcode += b"\x24\x88\x00\x00\x00\x48\xB8\x20\x62\x18\x43\x01\x00\x00\x00\x48"
	shellcode += b"\x8B\x00\x48\x89\x44\x24\x70\x48\xB8\x80\x76\xA6\x40\x01\x00\x00"
	shellcode += b"\x00\x48\x89\x84\x24\x90\x00\x00\x00\x48\xB8\x60\x71\x18\x43\x01"
	shellcode += b"\x00\x00\x00\x48\x8B\x00\x48\x89\x44\x24\x58\x48\xB8\xD0\xD7\x4A"
	shellcode += b"\x44\x01\x00\x00\x00\x48\x8B\x00\x48\x8B\x40\x68\x48\x89\x44\x24"
	shellcode += b"\x60\x48\xB8\xF8\x41\xEC\x42\x01\x00\x00\x00\x48\x8B\x00\x48\x89"
	shellcode += b"\x44\x24\x30\x48\x83\x7C\x24\x30\x00\x0F\x84\xE1\x01\x00\x00\x48"
	shellcode += b"\x8B\x44\x24\x30\x83\x78\x04\x00\x74\x09\x8B\x44\x24\x38\xE9\xCE"
	shellcode += b"\x02\x00\x00\x48\xB8\xD8\x2D\x52\x44\x01\x00\x00\x00\x48\x8B\x00"
	shellcode += b"\x48\x89\x44\x24\x78\x48\x8B\x44\x24\x78\x8B\x80\x08\x09\x00\x00"
	shellcode += b"\x89\x44\x24\x48\x48\x8B\x44\x24\x30\x8B\x00\x39\x44\x24\x48\x75"
	shellcode += b"\x09\x8B\x44\x24\x38\xE9\x97\x02\x00\x00\x48\x8B\x44\x24\x30\x8B"
	shellcode += b"\x4C\x24\x48\x89\x08\x48\x8B\x44\x24\x30\xC7\x40\x04\x01\x00\x00"
	shellcode += b"\x00\xB1\x01\xFF\x54\x24\x68\x88\x44\x24\x20\x33\xD2\x48\x8B\x4C"
	shellcode += b"\x24\x60\xFF\x94\x24\x80\x00\x00\x00\x48\x8B\x4C\x24\x30\x48\x89"
	shellcode += b"\x41\x08\xC7\x44\x24\x24\x00\x00\x00\x00\xEB\x0A\x8B\x44\x24\x24"
	shellcode += b"\xFF\xC0\x89\x44\x24\x24\x83\x7C\x24\x24\x46\x7D\x6E\x8B\x54\x24"
	shellcode += b"\x24\x48\x8B\x4C\x24\x60\xFF\x94\x24\x88\x00\x00\x00\x48\x63\x4C"
	shellcode += b"\x24\x24\x48\x8B\x54\x24\x30\x48\x8B\x52\x10\x48\x89\x04\xCA\x48"
	shellcode += b"\x63\x44\x24\x24\x48\x8B\x4C\x24\x30\x48\x8B\x49\x10\x48\x83\x3C"
	shellcode += b"\xC1\x00\x75\x35\x8B\x44\x24\x24\x89\x44\x24\x3C\xEB\x0A\x8B\x44"
	shellcode += b"\x24\x3C\xFF\xC0\x89\x44\x24\x3C\x83\x7C\x24\x3C\x46\x7D\x18\x48"
	shellcode += b"\x63\x44\x24\x3C\x48\x8B\x4C\x24\x30\x48\x8B\x49\x10\x48\xC7\x04"
	shellcode += b"\xC1\x00\x00\x00\x00\xEB\xD7\xEB\x02\xEB\x81\x0F\xB6\x44\x24\x20"
	shellcode += b"\x85\xC0\x74\x06\x33\xC9\xFF\x54\x24\x68\xC7\x44\x24\x28\x00\x00"
	shellcode += b"\x00\x00\xEB\x0A\x8B\x44\x24\x28\xFF\xC0\x89\x44\x24\x28\x83\x7C"
	shellcode += b"\x24\x28\x20\x0F\x8D\x8D\x00\x00\x00\x48\x63\x44\x24\x28\x48\x8B"
	shellcode += b"\x4C\x24\x30\x48\x8B\x49\x18\x48\x83\x3C\xC1\x00\x75\x02\xEB\x76"
	shellcode += b"\x48\x63\x44\x24\x28\x48\x8B\x4C\x24\x30\x48\x8B\x49\x18\x48\x8B"
	shellcode += b"\x04\xC1\x48\x8B\x40\x68\x48\x89\x84\x24\xA0\x00\x00\x00\x48\x63"
	shellcode += b"\x44\x24\x28\x48\x8B\x4C\x24\x30\x48\x8B\x49\x18\x48\x8B\x04\xC1"
	shellcode += b"\x48\x8B\x40\x70\x48\x89\x84\x24\xA8\x00\x00\x00\x48\xC7\x84\x24"
	shellcode += b"\xB0\x00\x00\x00\x00\x00\x00\x00\x48\x8D\x8C\x24\x98\x00\x00\x00"
	shellcode += b"\xFF\x94\x24\x90\x00\x00\x00\x48\x63\x44\x24\x28\x48\x8B\x4C\x24"
	shellcode += b"\x30\x48\x8B\x49\x20\x48\x8B\x94\x24\xB0\x00\x00\x00\x48\x89\x14"
	shellcode += b"\xC1\xE9\x5E\xFF\xFF\xFF\x48\x8B\x44\x24\x30\xC7\x40\x04\x00\x00"
	shellcode += b"\x00\x00\x8B\x44\x24\x38\xE9\x06\x01\x00\x00\xE9\x01\x01\x00\x00"
	shellcode += b"\x4C\x8D\x4C\x24\x4C\x41\xB8\x40\x00\x00\x00\xBA\x00\x10\x00\x00"
	shellcode += b"\x48\xB9\x00\x40\xEC\x42\x01\x00\x00\x00\xFF\x54\x24\x70\xB9\x28"
	shellcode += b"\x00\x00\x00\xFF\x54\x24\x58\x48\xB9\xF8\x41\xEC\x42\x01\x00\x00"
	shellcode += b"\x00\x48\x89\x01\x4C\x8D\x4C\x24\x4C\x44\x8B\x44\x24\x4C\xBA\x00"
	shellcode += b"\x10\x00\x00\x48\xB9\x00\x40\xEC\x42\x01\x00\x00\x00\xFF\x54\x24"
	shellcode += b"\x70\x48\xB8\xF8\x41\xEC\x42\x01\x00\x00\x00\x48\x8B\x00\x48\x89"
	shellcode += b"\x44\x24\x50\xC7\x44\x24\x40\x00\x00\x00\x00\xEB\x0A\x8B\x44\x24"
	shellcode += b"\x40\xFF\xC0\x89\x44\x24\x40\x48\x63\x44\x24\x40\x48\x83\xF8\x28"
	shellcode += b"\x73\x10\x48\x63\x44\x24\x40\x48\x8B\x4C\x24\x50\xC6\x04\x01\x00"
	shellcode += b"\xEB\xDB\xB9\x30\x02\x00\x00\xFF\x54\x24\x58\x48\x8B\x4C\x24\x50"
	shellcode += b"\x48\x89\x41\x10\xB9\x00\x01\x00\x00\xFF\x54\x24\x58\x48\x8B\x4C"
	shellcode += b"\x24\x50\x48\x89\x41\x18\xC7\x44\x24\x44\x00\x00\x00\x00\xEB\x0A"
	shellcode += b"\x8B\x44\x24\x44\xFF\xC0\x89\x44\x24\x44\x48\x63\x44\x24\x44\x48"
	shellcode += b"\x3D\x00\x01\x00\x00\x73\x14\x48\x63\x44\x24\x44\x48\x8B\x4C\x24"
	shellcode += b"\x50\x48\x8B\x49\x18\xC6\x04\x01\x00\xEB\xD5\xB9\x00\x01\x00\x00"
	shellcode += b"\xFF\x54\x24\x58\x48\x8B\x4C\x24\x50\x48\x89\x41\x20\x8B\x44\x24"
	shellcode += b"\x38\x48\x81\xC4\xC8\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC"

	# Replacing shellcode constants with updates via sigs
	shellcode = shellcode.replace((0x142EC41F8).to_bytes(8,'little'), offsets['NODICE_MGR'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x142EC4000).to_bytes(8,'little'), (offsets['NODICE_MGR']&(0xfffffffffffff000)).to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x142EC41F0).to_bytes(8,'little'), offsets['ORIGINAL_GTID_FUNC'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x14163F290).to_bytes(8,'little'), offsets['GET_LOCAL_PLAYER_FUNC'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x147B3D840).to_bytes(8,'little'), offsets['THREAD_CONTROL_FUNC'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x1444AD7D0).to_bytes(8,'little'), offsets['CLIENT_GAME_CONTEXT'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x141640090).to_bytes(8,'little'), offsets['GET_PLAYER_BY_INDEX_FUNC'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x143187160).to_bytes(8,'little'), offsets['GAME_MALLOC'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x143186220).to_bytes(8,'little'), offsets['GAME_VIRTUALPROTECT'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x143186528).to_bytes(8,'little'), offsets['GAME_GET_CURRENT_THREAD_ID'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x1444B5288).to_bytes(8,'little'), offsets['GAME_APPROVED_THREAD'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x144522DD8).to_bytes(8,'little'), offsets['DX11RENDERER'].to_bytes(8,'little'),len(shellcode))
	shellcode = shellcode.replace((0x140A67680).to_bytes(8,'little'), offsets['GET_ENTITY_DATA'].to_bytes(8,'little'),len(shellcode))
	
	ogtid = c_ulonglong() 
	tmp = c_ulonglong() 

	mem = MemAccess(pHandle)

	# Check the pointer swap to see if pointer manager is already installed
	if (mem[offsets['GAME_GET_CURRENT_THREAD_ID']](0).me() == offsets['CODECAVE_ADDR']):
		print ("[+] Pointer Manager Already Installed")
		return

	# Retrieve addr for GetCurrentThreadId() inside the IAT
	api.ReadProcessMemory(pHandle,LPCVOID(offsets['GAME_GET_CURRENT_THREAD_ID']),byref(ogtid),c_int(8),None)
	protection = DWORD()
	# Make our code cave writable
	api.VirtualProtectEx(pHandle,LPVOID(offsets['CODECAVE_ADDR']&PAGE_FLR),c_int(PAGE_SIZE),DWORD(PAGE_RWX),byref(protection))
	# Take the true GCTID() addr and write it to our code cave, as a global static pointer
	api.WriteProcessMemory(pHandle,LPCVOID(offsets['ORIGINAL_GTID_FUNC']),byref(ogtid),c_int(8),None)
	# Prepare a buffer with our shell code
	buff = (c_ubyte * len(shellcode)).from_buffer_copy(shellcode)
	# Write our shell code into the code cave
	api.WriteProcessMemory(pHandle,LPCVOID(offsets['CODECAVE_ADDR']),buff,c_int(len(shellcode)),None)
	# Close up the cave with original memory protections
	api.VirtualProtectEx(pHandle,LPVOID(offsets['CODECAVE_ADDR']&PAGE_FLR),c_int(PAGE_SIZE),protection,byref(protection))
	# Next, lets modify memory protections of IAT to hook GCTID and point it to our codecave
	api.VirtualProtectEx(pHandle,LPVOID(offsets['GAME_GET_CURRENT_THREAD_ID']&PAGE_FLR),c_int(PAGE_SIZE),DWORD(PAGE_RWX),byref(protection))
	# Open the flood gates, replace original GCTID() funcptr with NoDiceHandler()
	api.WriteProcessMemory(pHandle,LPCVOID(offsets['GAME_GET_CURRENT_THREAD_ID']),byref(c_ulonglong(offsets['CODECAVE_ADDR'])),c_int(8),None)
	# Close up the cave with original memory protections
	api.VirtualProtectEx(pHandle,LPVOID(offsets['GAME_GET_CURRENT_THREAD_ID']&PAGE_FLR),c_int(PAGE_SIZE),protection,byref(protection))
	print ("[+] Pointer Manager Successfully Installed")


