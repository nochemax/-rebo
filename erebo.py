import os
import time
import sys
import threading

from subprocess import Popen, PIPE, STDOUT
from netdiscover import *

import pandas as pd
from io import open

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ variables $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


listamenu=["Menu de Opciones:", "1--seleccion interfaz ", "2--DCHP ","3--Config memory kernel ","4--config ip y port locales","5--Exit"]#Menu Princcipal

ip_router=""
ip_rango=[]
ip_rv=[]
ip_ataque=""
ip_total=8
ip_intrusa=""
wlan=""
exit=False


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ MENU PRINCIPAL $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


def menu():

	print("\033[1;31;1m ")
	os.system('figlet    Erebo')
	print("\033[1;37;1m ")
	print("            "+listamenu[0])
	print("\033[1;37;m ")
	print("            "+listamenu[1])
	print("            "+listamenu[2])
	print("            "+listamenu[3])
	print("            "+listamenu[4])
	print("            "+listamenu[5])


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ menu seleccion interfaz $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


def selec_wlan(wlan):
	while True:
		try:
			wlan=input("Introduzca interfaz telnet: ")
			
			return wlan
			break

		except TypeError:
			print("error selec interfaz")


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ config proteccion DHCP $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


def p0f_DHCP(wlan, **datos):
	
	process = Popen(['uxterm', '-e', 'p0f', '-i', wlan, '-p', '-o', '/root/captura_intruso.csv'], stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()
	print (stdout)	


def hp3_DHCP(ip_intrusa, **datos):
	
	process1 = Popen(['uxterm', '-e', 'hping3', '--rand-source', '-p', '80', '-S', '--flood', ip_intrusa], stdout=PIPE, stderr=PIPE)
	stdout, stderr = process1.communicate()
	print (stdout)
	

def Menu_DHCP ( ip_router, ip_rango ):

	ip_rsl=0
	ip_min=0
	ip_max=0
	pase=""

	while True:

		try:
			print("configure DHCP ")
			pase=(input("selecccion manual = Y o automatico = N "))
	
			if(pase=="Y"):
				ip_router=(input("Introduzca ip_router: "))
				ip_rango=(input("Introduzca ipS separe con , : "))		
				print("Ip Router: "+ip_router)

			else:
				ip_router=(input("Introduzca ip_router: "))
				print("Ip Router: "+ip_router)
				ip_min=(int(input("Introduzca rango ip_router min 1: ")))
				ip_max=(int(input("Introduzca rango ip_router max 255: ")))


			print("configure calculate DHCP ")
	
			ip_rsl=ip_max - ip_min
			ip_cont=(ip_min)
			print(ip_rsl)

			for ip_cont in range (ip_rsl):

				ip_cont=(ip_cont+1)
				ip_contF=(str(ip_cont))
				ip_new=(str("192.168.1."+ip_contF))
				print(ip_new)
				ip_rango.append("192.168.1."+ip_contF)
		

			return ip_router, ip_rango
			break

		except TypeError:
			print("introduzca datos de nuevo ")


def DHCP ():

	while True:

		try:
			ip_h=(0)
			ip_volcado=""
			mystr="'"
			print("ip calculate")
			disc = Discover()
			p=disc.scan(ip_range="192.168.1.0/24")
			print("comprobacion estados ip")
			print(p)
			print("ordenandos datos comprobacion")
			df=pd.DataFrame(p, columns=['ip'])
			print(df)
			print('\n')
			print("generando salida de datos")
			ip_h=df['ip'].tolist()	
			print(ip_h)
			print("limpiando datos str")
	
			for i in ip_h:
		
				ip_volcado=(str(i))
				ip_volcado1=ip_volcado.replace('b','')
				ip_volcado2=ip_volcado1.replace(mystr,'') 
				print(ip_volcado2)
				ip_rv.append(ip_volcado2)

			return ip_rv
			break

		except TypeError:
			print("introduzca datos de nuevo ")



def DHCP_VyA(ip_rango, ip_rv):


	while True:

		try:
			if(ip_rv==ip_rango):
		
				print("DHCP SEGURO")
	
			else:
		
				print("detectada ip intrusa")
				print("procesando datos ip ")
		
				q=(len(ip_rango))
				w=(len(ip_rv))
				e=(q-w)
				ip_intrusa=(ip_rv[e])
				print("Mostrando datos de proceso")
				print(q, "-", w, "=", e)
				print("--------------------------")
				print("capturando datos del intruso", ip_intrusa )
				print("--------------------------")					
				y = threading.Thread(target=p0f_DHCP, args=(wlan,))
				y.start()				
				os.system('nmap -sV -O '+ip_intrusa)
				os.system('pkill p0f')
				print("captura de datos terminada")
				print("--------------------------")		 
				print("Jodiendo al intruso")		
				print("--------------------------")
				u = threading.Thread(target=hp3_DHCP, args=(ip_intrusa,))
				u.start()

				key=(input("Detener el ataque (Y/N: "))
				if( key == "Y" ):
					os.system('pkill hping3')
			break

		except TypeError:
			print("introduzca datos de nuevo ")		

		# 5* = complet
		#p0f     ****
		#nmap    ****
		#hping3  ****
	
#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$	Config memory kernel $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$				
#|- procesando config memoria kernel 
#|
#|--PRoc
#|
#|-- Paquete maliciosos (Marcianos) 
#|
#|-- Syn Cookies (bufer handshake)
#|
#|-- Ip Connection Tracking -->






#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$4 loop program $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

while exit==False:
	
	menu()
	key=(int(input("            "+"Select: ")))
	
	if (key==1):

		selec_wlan(wlan)
	
	elif (key==2):
		
		Menu_DHCP ( ip_router, ip_rango )
		print(ip_rango)
		DHCP()
		print("final")
		print(ip_rv)
		DHCP_VyA(ip_rango, ip_rv)	
	
	elif (key==3):
		print("trabajando")
		
	
	elif (key==4):
		print("trabajando")

	elif (key==5):		
		exit=True
	
print("\033[1;31;1m ")	
print("Smp_A byTe_Dey_bYte_HackiNg")
print("\033[1;31;m ")
