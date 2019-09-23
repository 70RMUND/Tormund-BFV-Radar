import RadarSprites
import pygame
import BFV
import random
import math
import sys, os
import traceback
import time
import MemAccess
import struct
from ctypes import *
from ctypes.wintypes import *



def is_admin():
	try:
		is_admin = os.getuid() == 0
	except AttributeError:
		is_admin = windll.shell32.IsUserAnAdmin() != 0
	return is_admin

def is_python3():
	if sys.version_info[0] < 3:
		return False
	return True
	
def get_pythonArch():
	bitness = (8 * struct.calcsize("P"))
	return bitness
  
GetAsyncKeyState = cdll.user32.GetAsyncKeyState
  
class Color:
	BLACK = (0, 0, 0)
	WHITE = (255, 255, 255)
	BLUE = (0, 0, 255)
	GREEN = (0, 255, 0)
	RED = (255, 0, 0)
	YELLOW = (255, 255,0)
	CYAN = (0, 255,255)
  
def Vec3Difference(a,b):
	ret = (c_float*3)()
	for i in range(3): ret[i] = a[i] - b[i]
	return ret
	
def Vec3Length(a):
	return math.sqrt((a[0]*a[0]) + (a[1]*a[1]) + (a[2]*a[2]))
	
def Vec3Normalize(a,limit):
	ret = (c_float*3)()
	if len != 0:
		for i in range(3): ret[i] = a[i]/limit
	return ret
	
def Vec3Scale(a,scale):
	ret = (c_float*3)()
	for i in range(3): ret[i] = a[i]*scale
	return ret
	
def Vec3Sum(a,b):
	ret = (c_float*3)()
	for i in range(3): ret[i] = a[i]+b[i]
	return ret
	
def rotate_point(pos, cen, angle, angle_in_radians=True):
	angle *= math.pi / 180
	cos_theta = math.cos(angle)
	sin_theta = math.sin(angle)
	
	ret = (c_float*3)()
	
	ret[0] = (cos_theta * (pos[0] - cen[0]) - sin_theta * (pos[2] - cen[2])) + cen[0]
	ret[1] = 0
	ret[2] = (sin_theta * (pos[0] - cen[0]) + cos_theta * (pos[2] - cen[2])) + cen[2]
	return ret

class Radar():
	def __init__(self,width,height):
		# Initialize PyGame
		pygame.init()
		pygame.display.init()
		
		# Load Sprites
		self.gfx = RadarSprites.RadarSprites()
		
		# Randomize Window Title
		random.seed(int(time.time()))
		caption = ""
		for i in range(random.randint(5, 15)):
			caption += chr((random.randint(65, 90),random.randint(97, 122))[random.randint(0, 1)])
		pygame.display.set_caption(caption)
		self.caption = caption
		
		# Set Screen Parameters
		self.height = height
		self.width = width
		self.screen = pygame.display.set_mode((self.width, self.height))
		self.distance = self.height
		self.zoom = 2.0
		
		# Initialize Fonts
		self.myfont = pygame.font.SysFont('Arial', 16)
		self.myfontbig = pygame.font.SysFont('Arial', 30)
		
		# Initialize Update Count
		self.UpdateCount = 0
		
		# -- ALWAYS ON TOP OPTIONAL SETTING --
		# NOTE: Uncomment the following 2 lines of code to have
		# your pygame window stay always on top of every window
		#
		# WARNING: KEEPING THE WINDOW ON TOP OF THE GAME WINDOW
		# MAKES YOU SUSCEPTIBLE TO ANTI-SHEET SCREEN SHOT DETECTION
		#
		#api = MemAccess.WinApi()
		#api.set_topmost("pygame", self.caption)
	
	def quit(self):
		pygame.display.quit()
		
	def GetRadarData(self,MyPosition,MyViewmatrix,Transform):
		try:
			Pos = Transform[3]
		except:
			Pos = [0,0,0,0]
			#print (str(Transform))
			#return (0,0,0)
		Pos = Vec3Difference(MyPosition,Pos)
		Pos = Vec3Normalize(Pos,self.distance/8)
		Pos = Vec3Scale(Pos,(self.distance/8)*self.zoom)
		angle = 360 - (math.atan2(-MyViewmatrix[0][0], MyViewmatrix[2][0]) * (180/math.pi))
		sangle = (math.atan2(-Transform[0][0], Transform[2][0]) * (180/math.pi))
		Pos = rotate_point(Pos,(0,0,0),angle)
		Pos = (-Pos[2], Pos[0]) # Change to vec2
		return (Pos,sangle-angle,angle)

	# Draw Enemy/Friend Arrow + Angle
	def DrawArrow(self,x,y,color,angle=0):
		def rotate(pos, angle):	
			cen = (5+x,0+y)
			angle *= -(math.pi/180)
			cos_theta = math.cos(angle)
			sin_theta = math.sin(angle)
			ret = ((cos_theta * (pos[0] - cen[0]) - sin_theta * (pos[1] - cen[1])) + cen[0],
			(sin_theta * (pos[0] - cen[0]) + cos_theta * (pos[1] - cen[1])) + cen[1])
			return ret
		
		p0 = rotate((0+x  ,-4+y),angle+90)
		p1 = rotate((0+x  ,4+y ),angle+90)
		p2 = rotate((10+x ,0+y ),angle+90)
		
		pygame.draw.polygon(self.screen, color, [p0,p1,p2])
	
	# Transposes center based coordinates to top/left based coordinates
	def FromCenter(self,x,y):
		class point():
			def __init__(self,x,y):
				self.x = x;self.y = y;
		return point(int((self.width/2)+x),int((self.height/2)+y))
		
		
	def UpdateObjectives(self,data):
		for CapturePoint in data.capturepoints:
			if CapturePoint.objectivedata == None:
				RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,CapturePoint.transform)
				Pos = RadarData[0]
				Yaw = RadarData[1]
				Position = self.FromCenter(Pos[0],Pos[1])
				if (CapturePoint.initialteamowner == data.myteamid):
					textsurface = self.myfontbig.render(hex(CapturePoint.pointer), False, Color.GREEN)
					self.screen.blit(textsurface,(Position.x-2,Position.y-1))
				else:
					textsurface = self.myfontbig.render(hex(CapturePoint.pointer), False, Color.RED)
					self.screen.blit(textsurface,(Position.x-2,Position.y-1))
		
		for UIObjective in data.uiobjectives:
			RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,UIObjective.transform)
			Pos = RadarData[0]
			Yaw = RadarData[1]

			Position = self.FromCenter(Pos[0],Pos[1])

			if (UIObjective.teamstate == 1):
				self.screen.blit(self.gfx.flaggreen,(Position.x,Position.y-20))
				textsurface = self.myfont.render(UIObjective.shortname, False, Color.GREEN)
			else:
				self.screen.blit(self.gfx.flagred,(Position.x,Position.y-20))
				textsurface = self.myfont.render(UIObjective.shortname, False, Color.RED)
			self.screen.blit(textsurface,(Position.x-2,Position.y-1))

	def UpdateExplosives(self,data):
		for Explosive in data.explosives:
			RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,Explosive.transform)
			Pos = RadarData[0]
			Yaw = RadarData[1]
			Position = self.FromCenter(Pos[0],Pos[1])
			textsurface = self.myfont.render("x", False, (Color.RED,Color.GREEN)[data.myteamid == Explosive.teamid])
			self.screen.blit(textsurface,(Position.x,Position.y))
			
	def UpdateGrenades(self,data):
		for Grenade in data.grenades:
			RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,Grenade.transform)
			Pos = RadarData[0]
			Yaw = RadarData[1]
			Position = self.FromCenter(Pos[0],Pos[1])
			if((cnt%16)>= 8):textsurface = self.myfont.render("G", False, Color.RED)
			else: textsurface = self.myfont.render("G", False, Color.GREEN)
			self.screen.blit(textsurface,(Position.x,Position.y))
			
			
	def UpdateSupplies(self,data):
		for Supply in data.supplies:
			RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,Supply.transform)
			Pos = RadarData[0]
			Yaw = RadarData[1]
			Position = self.FromCenter(Pos[0],Pos[1])
			if (Supply.name == "Supply_Ammo_Station"):
				self.screen.blit(self.gfx.ammospot,(Position.x,Position.y))
			elif (Supply.name == "Supply_Medical_Station"):
				self.screen.blit(self.gfx.health,(Position.x,Position.y))
			else:
				continue		

	def UpdateSoldiers(self,data):
		# Main Soldier Entity Render Loop
		for Soldier in data.soldiers:
			# Check if soldier is enemy based on teamid
			Enemy = (False,True)[data.myteamid != Soldier.teamid]
			# If the soldier is in a vehicle lets skip rendering it
			if Soldier.vehicle:
				continue
				
			RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,Soldier.transform)
			Pos = RadarData[0]
			Yaw = RadarData[1]
				
			# Transpose soldier coordinates to radar
			Position = self.FromCenter(Pos[0],Pos[1])
			
			if Soldier.alive:
				# if our soldier is alive we draw an arrow in the direction of its yaw
				# we color the soldier based on if it is an enemy or not
				self.DrawArrow(Position.x,Position.y,(Color.GREEN,Color.RED)[Enemy],Yaw)
			else:
				if (Enemy):
					# if we have a dead enemy soldier mark it with red skull
					self.screen.blit(self.gfx.deadiconred,(Position.x,Position.y))
				else:
					# if we have a dead team soldier mark it with green skull
					self.screen.blit(self.gfx.deadicongreen,(Position.x,Position.y))
					
	def DrawTank(self,Position,yaw,VColor):
		if (VColor == Color.RED):
			rot = pygame.transform.rotate(self.gfx.tankred,yaw)				
		elif (VColor == Color.GREEN):
			rot = pygame.transform.rotate(self.gfx.tankgreen,yaw)
		else:
			rot = pygame.transform.rotate(self.gfx.tankwhite,yaw)
		self.screen.blit(rot,(Position.x-7,Position.y-15))
				
	def DrawPlane(self,Position,yaw,VColor):
		if (VColor == Color.RED):
			rot = pygame.transform.rotate(self.gfx.planered,yaw)				
		elif (VColor == Color.GREEN):
			rot = pygame.transform.rotate(self.gfx.planegreen,yaw)
		else:
			rot = pygame.transform.rotate(self.gfx.planewhite,yaw)
		self.screen.blit(rot,(Position.x-14,Position.y-20))
		
	def DrawBeacon(self,Position,VColor):
		if (VColor == Color.RED):
			self.screen.blit(self.gfx.beaconiconred,(Position.x,Position.y))
		elif (VColor == Color.GREEN):
			self.screen.blit(self.gfx.beaconicongreen,(Position.x,Position.y))
		else:
			self.screen.blit(self.gfx.beaconiconwhite,(Position.x,Position.y))
			
	def DrawStationary(self,Position,VColor):
		if (VColor == Color.RED):
			self.screen.blit(self.gfx.stationgunred,(Position.x,Position.y))
		elif (VColor == Color.GREEN):
			self.screen.blit(self.gfx.stationgungreen,(Position.x,Position.y))
		else:
			self.screen.blit(self.gfx.stationgunwhite,(Position.x,Position.y))
			
	def DrawTransport(self,Position,yaw,VColor):
		if (VColor == Color.RED):
			rot = pygame.transform.rotate(self.gfx.carred,yaw)				
		elif (VColor == Color.GREEN):
			rot = pygame.transform.rotate(self.gfx.cargreen,yaw)
		else:
			rot = pygame.transform.rotate(self.gfx.carwhite,yaw)
		self.screen.blit(rot,(Position.x-12,Position.y-20))
				
	def UpdateVehicles(self,data):
			# Main Vehicle Render Loop
		for Vehicle in data.vehicles:
				
			RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,Vehicle.transform)
			Pos = RadarData[0]
			Yaw = RadarData[1]

			# Transpose vehicle coordinates to radar
			Position = self.FromCenter(Pos[0],Pos[1])
			
			# Set a color based on vehicle's association
			# Green if friendly
			# Red if enemy
			# White is neutral
			if (data.myteamid == Vehicle.teamid):
				VColor = Color.GREEN
			elif (Vehicle.teamid):
				VColor = Color.RED
			else:
				VColor = Color.WHITE

			if "Stationary" in Vehicle.vehicletype:
				self.DrawStationary(Position,VColor)
			elif "Towable" in Vehicle.vehicletype:
				self.DrawStationary(Position,VColor)
			elif "Tank" in Vehicle.vehicletype:
				self.DrawTank(Position,Yaw,VColor)
			elif "ArmoredCar" in Vehicle.vehicletype:
				self.DrawTank(Position,Yaw,VColor)
			elif "Halftrack" in Vehicle.vehicletype:
				self.DrawTank(Position,Yaw,VColor)
			elif "Airplane" in Vehicle.vehicletype:
				self.DrawPlane(Position,Yaw,VColor)
			elif "SpawnBeacon" in Vehicle.vehicletype:
				self.DrawBeacon(Position,VColor)
			else:
				self.DrawTransport(Position,Yaw,VColor)
	
	def DrawDot(self,pos,color):
		self.screen.set_at((pos[0], pos[1]-1), color)
		self.screen.set_at((pos[0]+1, pos[1]-1), color)
		self.screen.set_at((pos[0]-1, pos[1]-1), color)
		self.screen.set_at((pos[0], pos[1]), color)
		self.screen.set_at((pos[0]+1, pos[1]), color)
		self.screen.set_at((pos[0]-1, pos[1]), color)
		self.screen.set_at((pos[0], pos[1]+1), color)
		self.screen.set_at((pos[0]+1, pos[1]+1), color)
		self.screen.set_at((pos[0]-1, pos[1]+1), color)
	
	
	def UpdateBounds(self,data):
		for t in range(2,-1,-1):
			if (t == 2): C = (Color.RED,Color.GREEN)[(data.myteamid-1) % (2)]
			elif (t == 1): C = (Color.GREEN,Color.RED)[(data.myteamid-1) % (2)]
			else: C = (252, 164, 40)
			
			for Shape in data.boundsdata[t]:
				PointTransformed = []
				for Point in Shape.points:
					RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,[([0]*4),([0]*4),([0]*4),[Point[0],0,Point[2],0]])
					Pos = RadarData[0]
					Pos = self.FromCenter(Pos[0],Pos[1])
					PointTransformed += [(Pos.x,Pos.y)]
				if len(PointTransformed) > 1:
					pygame.draw.polygon(self.screen, C, PointTransformed,3)
			
	def UpdateFirestorm(self,data):
		if (data.circledata != None):
			c = data.circledata

			RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,[[0,0,0,0],[0,0,0,0],[0,0,0,0],c.OuterCircle_Moving])
			Pos = RadarData[0]
			Yaw = RadarData[1]
			Position = self.FromCenter(Pos[0],Pos[1])
			rad = c.OuterCircleRadius_Moving * self.zoom
			if (int(rad)>3):
				pygame.draw.circle(self.screen,(246,108,0),(Position.x,Position.y),int(rad),3)
			
			RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,[[0,0,0,0],[0,0,0,0],[0,0,0,0],c.InnerCircle_Const])
			Pos = RadarData[0]
			Yaw = RadarData[1]
			Position = self.FromCenter(Pos[0],Pos[1])	
			rad = c.InnerCircleRadius_Const * self.zoom
			if (int(rad)>3):
				pygame.draw.circle(self.screen,(55,229,251),(Position.x,Position.y),int(rad),3)
			
		for LootEntityPtr in data.loots:	
			LootEntity = data.loots[LootEntityPtr]
			RadarData = self.GetRadarData(data.mytransform[3],data.myviewmatrix,LootEntity.transform)
			Pos = RadarData[0]
			Yaw = RadarData[1]
			Position = self.FromCenter(Pos[0],Pos[1])
			x = Position.x
			y = Position.y

			if ("U_Dakar_Bandages" in LootEntity.ItemName):
				color = Color.RED
				self.DrawDot((x,y),color)
			elif ("FlareGun" in LootEntity.ItemName):
				if ("V1Rocket" in LootEntity.ItemName):
					color = Color.GREEN
					self.Text("F",color,x,y)
				elif ("DangerZone" in LootEntity.ItemName):
					color = Color.RED
					self.Text("F",color,x,y)
			elif ("U_BREN" in LootEntity.ItemName):
				if (LootEntity.LootName[-5:] == "Tier2"):
					color = Color.GREEN
					self.Text("B",color,x,y)
				elif (LootEntity.LootName[-5:] == "Tier3"):
					color = self.blink()
					self.Text("B",color,x,y)
				else:
					color = Color.WHITE
					self.Text("B",color,x,y)
			elif ("BoltAction" in LootEntity.ItemName):
				if (LootEntity.LootName[-5:] == "Tier2"):
					color = Color.GREEN
					self.Text("S",color,x,y)
				elif (LootEntity.LootName[-5:] == "Tier3"):
					color = self.blink()
					self.Text("S",color,x,y)
				else:
					color = Color.WHITE
					self.Text("S",color,x,y)
			elif ("Armor" in LootEntity.ItemName):
				color = Color.YELLOW
				self.DrawDot((x,y),color)
			elif ("Ammo" in LootEntity.ItemName):
				if ("U_Dakar_Ammo_Sniper" in LootEntity.ItemName):
					color = Color.GREEN
					self.DrawDot((x,y),color)
				elif ("U_Dakar_Ammo_MG" in LootEntity.ItemName):
					color = Color.CYAN
					self.DrawDot((x,y),color)
				else:
					color = Color.WHITE
					self.Text(".",color,x,y)
			elif LootEntity.VestEntity:
				if (LootEntity.LootName[-5:] == "Tier3"):
					color = self.blink()
					self.Text("A",color,x,y)
				else:
					color = Color.YELLOW
					self.Text("A",color,x,y)
			else:
				color = Color.WHITE
				self.Text(".",color,x,y)

			
	def blink(self):
		global cnt
		if ((cnt%16)>= 8):
			return Color.RED
		return Color.GREEN
		
	def Text(self,text,color,x,y):
		textsurface = self.myfont.render(text, False, color)
		self.screen.blit(textsurface,(x,y))
			
	# The main PyGame render loop, this takes a GameData object
	# which contains information on all relvant entities and draws
	# them onto the radar
	def Update(self):
		g_gamedata = BFV.g_gamedata

		for event in pygame.event.get():  # User did something
			if event.type == pygame.QUIT:  # If user clicked close
				pygame.quit()

		inc_factor = self.zoom/100.0 * 4

		if (GetAsyncKeyState(0x6b)&0x8000): # '+' key
			if (self.zoom <= 39.9): self.zoom += inc_factor
			else:  self.zoom = 40.0

		elif (GetAsyncKeyState(0x6d)&0x8000): # '-' key
			if (self.zoom >= 0.100001): self.zoom -= inc_factor
			else: self.zoom = 0.1		

		# Set our background first, everything else on top of it
		try:
			self.screen.fill(Color.BLACK)
		except:
			print("[+] Quitting...")
			exit(0)
			
		pygame.draw.line(self.screen, Color.RED, (self.width/2,0),(self.width/2,self.height))
		pygame.draw.line(self.screen, Color.RED, (0,self.height/2),(self.width,self.height/2))
		
		if (g_gamedata.valid):
			if (g_gamedata.mysoldier == 0):
				if (g_gamedata.circledata != None):
					c = g_gamedata.circledata
					g_gamedata.myviewmatrix = [[0,0,0,0],[0,0,0,0],[0,0,0,0],c.InnerCircle_Const]
					g_gamedata.mytransform = [[0,0,0,0],[0,0,0,0],[0,0,0,0],c.InnerCircle_Const]
					
			self.UpdateBounds(g_gamedata)
			self.UpdateVehicles(g_gamedata)
			self.UpdateObjectives(g_gamedata)
			self.UpdateGrenades(g_gamedata)
			self.UpdateExplosives(g_gamedata)
			self.UpdateSupplies(g_gamedata)
			self.UpdateFirestorm(g_gamedata)
			self.UpdateSoldiers(g_gamedata)
			


		pygame.display.update()
		self.UpdateCount += 1

def StartRadar():
	global cnt
	global rad
	rad = None
	print ("[+] Searching for BFV.exe...")
	phandle = BFV.GetHandle()
	if (phandle):
		time.sleep(1)
	else:
		print ("[+] Error: Cannot find BFV.exe")
		exit(1)
	print ("[+] BFV.exe found, Handle: 0x%x"%(phandle))
	
	BFV.initialize(phandle) # Gather offsets, patch the game
	
	print ("[+] Starting Radar...")
	rad = Radar(w,h)
	print ("[+] Done")
		
	cnt = 0
	while 1:
		BFV.Process(phandle,cnt) # this accesses game memory for data
		rad.Update() # this renders data to radar
		cnt += 1

if __name__ == "__main__":
	print ("[+] Tormund's External Radar v1.0 for Battlefield V")

	if (is_admin() == False):
		print ("[+] Error: python (or commandline) must be ran with admin privledges")
		input("Press Enter to continue...")
		exit(1)
	
	if (is_python3() == False):
		print ("[+] Error: detected Python 2, this script requires Python 3")
		raw_input("Press Enter to continue...")
		exit(1)
		
	arch = get_pythonArch()
	if (arch != 64):
		print ("[+] Error: detected Python 3.* %i-bit, this script requires Python 3 64-bit"% (arch))
		print ("[+] Error: you may need to reinstall python to a 3.* 64-bit version")
		input("Press Enter to continue...")
		exit(1)
	
	if len(sys.argv) == 1:
		w = 800
		h = 600

	elif len(sys.argv) != 3:
		print ("[+] Usage: python ./radar.py [radar width] [radar height]")
		input("Press Enter to continue...")
		exit(1)

	else:
		try:
			w = int(sys.argv[1])
			h = int(sys.argv[2])
		except:
			print ("[+] Error: Cannot parse arguments")
			print ("[+] Usage: python ./radar.py [radar width] [radar height]")
			input("Press Enter to continue...")
			exit(1)
			
	# Main exception trap
	try:
		StartRadar() # Start the rest of the radar setup
	except BaseException:
		global rad
		if (rad != None): rad.quit()
		if str(sys.exc_info()[0]) != "<class 'SystemExit'>":
			print ("[+] ")
			print ("[+] SEVERE: EXCEPTION CAUGHT!")
			print ("[+] \n")
			print(traceback.format_exc())
			print ("[+] ")
			print ("[+] Exiting Radar...")
	finally:
		input("Press Enter to continue...")

	
