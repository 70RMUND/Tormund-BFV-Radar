import pygame
import sys
import os

class RadarSprites():
	def __init__(self):
		
		scriptdir = os.path.dirname(os.path.realpath(__file__))
		
		# Stationary Gun White
		self.stationgunwhite = pygame.image.load(scriptdir+"/images/sentry-gun.png")
		self.stationgunwhite = pygame.transform.scale(self.stationgunwhite,(20,20))
		pygame.transform.threshold(self.stationgunwhite, self.stationgunwhite, search_color=(255,255,255,255), set_color=(0,0,0,0))
		
		# Stationary Gun Red 
		self.stationgunred = self.stationgunwhite.copy()
		pygame.transform.threshold(self.stationgunred, self.stationgunwhite, search_color=(0,0,0,255), set_color=(255,0,0,255))
		
		# Stationary Gun Green 
		self.stationgungreen = self.stationgunwhite.copy()
		pygame.transform.threshold(self.stationgungreen, self.stationgunwhite, search_color=(0,0,0,255), set_color=(0,255,0,255))
		
		# Dead Soldier Icon White
		self.deadicon = pygame.image.load(scriptdir+"/images/dead.png")
		self.force_black(self.deadicon)
		self.swap_pixels(self.deadicon,[0,0,0,0xFF],[0,0,0,0x0])
		self.deadicon = pygame.transform.scale(self.deadicon,(15,15))
		self.deadicongreen = self.deadicon.copy()
		self.deadiconred = self.deadicon.copy()
		
		# Dead Soldier Red
		self.swap_pixels(self.deadiconred,[0xFF,0xFF,0xFF,0xFF],[0xFF,0x0,0,0xFF])
		
		# Dead Soldier Green
		self.swap_pixels(self.deadicongreen,[0xFF,0xFF,0xFF,0xFF],[0x0,0xFF,0,0xFF])
		
		# SpawnBeacon Icon White
		self.beaconiconwhite = pygame.image.load(scriptdir+"/images/radio.png")
		self.beaconiconwhite = pygame.transform.scale(self.beaconiconwhite,(15,15))
		self.force_black(self.beaconiconwhite)
		self.swap_pixels(self.beaconiconwhite,[0,0,0,0xFF],[0,0,0,0x0])
		
		# SpawnBeacon Icon Red
		self.beaconiconred = self.beaconiconwhite.copy()
		self.swap_pixels(self.beaconiconred,[0xFF,0xFF,0xFF,0xFF],[0xFF,0x0,0,0xFF])
		
		# SpawnBeacon Icon Green
		self.beaconicongreen = self.beaconiconwhite.copy()
		self.swap_pixels(self.beaconicongreen,[0xFF,0xFF,0xFF,0xFF],[0x0,0xFF,0,0xFF])
		
		# Flag White 
		self.flagwhite = pygame.image.load(scriptdir+"/images/flag.png")
		self.flagwhite = pygame.transform.scale(self.flagwhite,(20,20))
		self.force_black(self.flagwhite)
		self.swap_pixels(self.flagwhite,[0,0,0,0xFF],[0,0,0,0x0])
		self.flagred = self.flagwhite.copy()
		self.flaggreen = self.flagwhite.copy()
		self.swap_pixels(self.flagred,[0xFF,0xFF,0xFF,0xFF],[0xFF,0,0,0xFF])
		self.swap_pixels(self.flaggreen,[0xFF,0xFF,0xFF,0xFF],[0x0,0xFF,0,0xFF])
		
		# Tank White 
		self.tankwhite = pygame.image.load(scriptdir+"/images/tank.png")
		self.tankwhite = pygame.transform.scale(self.tankwhite,(14,30))
		self.force_black(self.tankwhite)
		self.tankwhite = self.swap_pixels(self.tankwhite,[0,0,0,0xFF],[0,0,0,0x0])

		self.tankred = self.tankwhite.copy()
		self.tankgreen = self.tankwhite.copy()
		self.swap_pixels(self.tankred,[0xFF,0xFF,0xFF,0xFF],[0xFF,0,0,0xFF])
		self.swap_pixels(self.tankgreen,[0xFF,0xFF,0xFF,0xFF],[0x0,0xFF,0,0xFF])
		
		# Plane White 
		self.planewhite = pygame.image.load(scriptdir+"/images/plane.png")
		self.planewhite = pygame.transform.scale(self.planewhite,(28,40))
		self.force_black(self.planewhite)
		self.planewhite = self.swap_pixels(self.planewhite,[0,0,0,0xFF],[0,0,0,0x0])
		
		self.planered = self.planewhite.copy()
		self.planegreen = self.planewhite.copy()
		self.swap_pixels(self.planered,[0xFF,0xFF,0xFF,0xFF],[0xFF,0,0,0xFF])
		self.swap_pixels(self.planegreen,[0xFF,0xFF,0xFF,0xFF],[0x0,0xFF,0,0xFF])
		
		
		# Car White 
		self.carwhite = pygame.image.load(scriptdir+"/images/transport.png")
		self.carwhite = pygame.transform.scale(self.carwhite,(24,40))
		self.force_black(self.carwhite)
		self.carwhite = self.swap_pixels(self.carwhite,[0,0,0,0xFF],[0,0,0,0x0])
		
		self.carred = self.carwhite.copy()
		self.cargreen = self.carwhite.copy()
		self.swap_pixels(self.carred,[0xFF,0xFF,0xFF,0xFF],[0xFF,0,0,0xFF])
		self.swap_pixels(self.cargreen,[0xFF,0xFF,0xFF,0xFF],[0x0,0xFF,0,0xFF])
		
		# Health Red
		self.health = pygame.image.load(scriptdir+"/images/health.png")
		self.health = pygame.transform.scale(self.health,(20,20))
		self.swap_pixels(self.health,[0,0,0,0xFF],[0,0,0,0x0])
		self.swap_pixels(self.health,[0xFF,0xFF,0xFF,0xFF],[0,0,0xFF,0xFF])
		
		# Ammo Spot 
		self.ammospot = pygame.image.load(scriptdir+"/images/ammo_spot.png")
		self.ammospot = pygame.transform.scale(self.ammospot,(10,28))
		self.force_black(self.ammospot)
		self.ammospot = self.swap_pixels(self.ammospot,[0,0,0,0xFF],[0,0,0,0x0])
		self.swap_pixels(self.ammospot,[0xFF,0xFF,0xFF,0xFF],[0x0,0xFF,0,0xFF])
	
		
		# Explosive 
		self.explosive = pygame.image.load(scriptdir+"/images/explosive.png")
		self.explosive = pygame.transform.scale(self.explosive,(15,15))
		self.force_black(self.explosive)
		self.explosive = self.swap_pixels(self.explosive,[0,0,0,0xFF],[0,0,0,0x0])
		
		self.explosivered = self.explosive.copy()
		self.explosivegreen = self.explosive.copy()
		self.swap_pixels(self.explosivered,[0xFF,0xFF,0xFF,0xFF],[0xFF,0,0,0xFF])
		self.swap_pixels(self.explosivegreen,[0xFF,0xFF,0xFF,0xFF],[0x0,0xFF,0,0xFF])
		
		# Crate
		self.crate = pygame.image.load(scriptdir+"/images/crate.png")
		# Safe
		self.safe = pygame.image.load(scriptdir+"/images/safe.png")

	def swap_pixels(self,img,colorbefore,colorafter):
		width,height=img.get_size()
		for x in range(0,width):
			for y in range(0,height):
				r,g,b,a=img.get_at((x,y))
				if ((colorbefore[0] == r) and
					(colorbefore[1] == g) and
					(colorbefore[2] == b) and
					(colorbefore[3] == a)):
					img.set_at((x,y),(colorafter[0],colorafter[1],colorafter[2],colorafter[3]))
		return img
					
	def force_black(self,img):
		width,height=img.get_size()
		for x in range(0,width):
			for y in range(0,height):
				r,g,b,a=img.get_at((x,y))
				if (((r != 0) and (r != 0xFF)) or
					((g != 0) and (g != 0xFF)) or
					((b != 0) and (b != 0xFF))):
					if ((r+g+b) >= 0x180):
						img.set_at((x,y),(0xFF,0xFF,0xFF,a))
					else:
						img.set_at((x,y),(0x0,0x0,0x0,a))