#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: kaluche

# pip3 install py2neo
# pip3 install pandas
from py2neo import Graph
from prettytable import PrettyTable
import argparse
import datetime

class bcolors:
	RED = '\033[31m'
	YELLOW = '\033[33m'
	BLUE = '\033[34m'
	CGREY = '\33[90m'
	YELLOW2 = '\033[93m'
	CBLUE2 = '\33[94m'
	MAGNETA = '\033[35m'
	ENDC = '\033[0m'
	LIGHTGREEN = "\033[92m"

def args():
	parser = argparse.ArgumentParser(description="Quick win for bloodhound + neo4j")
	parser.add_argument('-b', '--bolt', type=str, default="bolt://127.0.0.1:7687", help="Neo4j bolt connexion (default: bolt://127.0.0.1:7687)")
	parser.add_argument('-u', '--username', type=str, default="neo4j", help="Neo4j username (default: neo4j)")
	parser.add_argument('-p', '--password', type=str, default="neo4j", help="Neo4j password (default: neo4j)")
	parser.add_argument('-y', '--years', type=int, default=None, help="Print enabled users where password is not changed for X year (default: 10)")
	parser.add_argument('-s', '--spool', dest="ladmin", default=False, action="store_true", help="Find all computer accounts that have local admin rights (SpoolSample+Relay)")
	parser.add_argument('-n', '--no-color', dest="color", default=True, action="store_false", help="Disable colors")
	parser.add_argument('--gpo', action='store_true')
	parser.add_argument('--computer', action='store_true')
	return parser.parse_args()

def print_title(t, color):
	pprint("###########################################################", color, bcolors.BLUE)
	pprint(f"[*] {t}", color, bcolors.BLUE)
	pprint("###########################################################\n", color, bcolors.BLUE)

def pretty(string, color=False, bcolor=bcolors.YELLOW2):
	return f"{bcolor}{string}{bcolors.ENDC}" if color else string

def pprint(fmt, color=True, bcolor=None, *args, **kwargs):
	fmt = f"{bcolor}{fmt}{bcolors.ENDC}" if color else fmt
	print(fmt, *args, **kwargs)


def checktimestamp(val, color=True):
	val = val.split(".")[0]
	res = (datetime.datetime.now() - datetime.datetime.fromtimestamp(int(val)))
	if (val) == "-1":
		return("NEVER")
	if (res > datetime.timedelta(days=365 * 10)) == True:
		string = f"{bcolors.RED}> 10 years{bcolors.ENDC}" if color else "> 10 years"
		return(string)
	elif (res > datetime.timedelta(days=365 * 5)) == True:
		string = f"{bcolors.RED}> 5 years{bcolors.ENDC}" if color else "> 5 years"
		return(string)
	elif (res > datetime.timedelta(days=365 * 3)) == True:
		string = f"{bcolors.RED}> 3 years{bcolors.ENDC}" if color else "> 3 years"
		return(string)
	elif (res > datetime.timedelta(days=365 * 2)) == True:
		string = f"{bcolors.RED}> 2 years{bcolors.ENDC}" if color else "> 2 years"
		return(string)
	elif (res > datetime.timedelta(days=365 * 1)) == True:
		string = f"{bcolors.MAGNETA}> 1 years{bcolors.ENDC}" if color else "> 1 years"
		return(string)
	elif (res < datetime.timedelta(days=365 )) == True:
		return("< 1 year")

def stats_return_count(query):
	req = g.run(query).to_table()
	return req[0][0]


def enum_DA(g, color):
	print_title("Enumerating all domains admins (rid:512|544) (recursive)", color)
	req = g.run("""MATCH p=(n:Group)<-[:MemberOf*1..]-(m) 
		WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)"
		RETURN DISTINCT m.name,m.enabled,m.hasspn,m.dontreqpreauth,m.unconstraineddelegation,m.lastlogontimestamp
		ORDER BY m.enabled DESC,m.name""").to_table()

	for u in req:
		val = pretty(u[0], color, bcolors.CGREY)
		if u[1] == False:
			print(f"[+] Domain admins (disabled) \t: {val}", end="")
		if u[1] == True:
			print(f"[+] Domain admins (enabled) \t: {val}", end="")
		if u[1] == None:
			print(f"[+] Domain admins (group) \t: {val}", end="")
		if u[2] == True:
			pprint(" [SPN]", color, bcolor=bcolors.YELLOW2, end="")
		if u[3] == True:
			pprint(" [ASREP]", color, bcolor=bcolors.YELLOW2, end="")
		if u[4] == True:
			pprint(" [UNCONSTRAINED]", color, bcolor=bcolors.YELLOW2, end="")
		if u[5]:
			fmt_time = checktimestamp(str(u[5]), color)
			pprint(f" [LASTLOG: {fmt_time}]", color, bcolors.CBLUE2, end="")
		print("")
	print("")

def enum_priv_SPN(g, color):
	print_title("Enumerating privileges SPN", color)
	req = g.run("""MATCH p=(n:Group)<-[:MemberOf*1..]-(m) 
		WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)"
		AND m.hasspn = TRUE 
		RETURN DISTINCT m.name,m.enabled 
		ORDER BY m.enabled DESC,m.name""").to_table()
	if not req:
		print('[-] No entries found')
	for u in req:
		if u[1] == False:
			pprint(f"[+] SPN DA (disabled) \t: {u[0]}", color, bcolors.CGREY)
		if u[1] == True:
			pprint(f"[+] SPN DA (enabled) \t: {u[0]}", color, bcolors.LIGHTGREEN)
	print("")

def enum_priv_AS_REP_ROAST(g, color):
	print_title("Enumerating privileges AS REP ROAST", color)
	req = g.run("""MATCH p=(n:Group)<-[:MemberOf*1..]-(m) 
		WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)" 
		AND m.dontreqpreauth = TRUE 
		RETURN DISTINCT m.name,m.enabled
		ORDER BY m.enabled DESC,m.name""").to_table()
	if not req:
		print('[-] No entries found')
	for u in req:
		if u[1] == False:
			pprint(f"[+] AS-Rep Roast DA (disabled) \t: {u[0]}", color, bcolors.CGREY)
		if u[1] == True:
			print(f"[+] AS-Rep Roast DA (enabled) \t: {u[0]}", color, bcolors.LIGHTGREEN)
	print("")

def enum_all_SPN(g, color):
	print_title("Enumerating all SPN", color)
	req = g.run("""MATCH (u:User) 
		WHERE u.hasspn = TRUE 
		RETURN u.name,u.enabled,u.admincount
		ORDER BY u.enabled DESC,u.name""").to_table()
	if not req:
		print('[-] No entries found')
	for u in req:
		if u[1] == False:
			pprint(f"[+] SPN (disabled) \t: {u[0]}", color, bcolors.CGREY, end="")
		if u[1] == True:
			pprint(f"[+] SPN (enabled) \t: {u[0]}", color, bcolors.LIGHTGREEN, end="")
		if u[2] == True:
			pprint(" [AdminCount]", color, bcolors.YELLOW2, end="")
		print("")
	print("")

def enum_asrep_roast(g, color):
	print_title("Enumerating AS-REP ROSTING", color)
	req = g.run("""MATCH (u:User) 
		WHERE u.dontreqpreauth = TRUE 
		RETURN u.name,u.enabled,u.admincount
		ORDER BY u.enabled DESC,u.name""").to_table()
	if not req:
		print('[-] No entries found')
	for u in req:
		if u[1] == False:
			pprint(f"[+] AS-Rep Roast (disabled) \t: {u[0]}", color, bcolors.CGREY, end="")
		if u[1] == True:
			pprint(f"[+] AS-Rep Roast (enabled) \t: {u[0]}", color, bcolors.LIGHTGREEN, end="")
		if u[2] == True:
			pprint(" [AdminCount]", color, bcolors.YELLOW2, end="")
		print("")
	print("")

def enum_unconstrained_account(g, color):
	print_title("Enumerating Unconstrained account", color)
	req = g.run("""MATCH (u:User) 
		WHERE u.unconstraineddelegation = TRUE 
		RETURN u.name,u.enabled,u.admincount
		ORDER BY u.enabled DESC,u.name""").to_table()
	if not req:
		print('[-] No entries found')
	for u in req:
		if u[1] == False:
			pprint(f"[+] Unconstrained user (disabled) \t: {u[0]}", color, bcolors.CGREY, end="")
		if u[1] == True:
			pprint(f"[+] Unconstrained user (enabled) \t: {u[0]}", color, bcolors.LIGHTGREEN, end="")
		if u[2] == True:
			pprint(" [AdminCount]", color, bcolors.YELLOW2, end="")
		print("")
	print("")

def enum_constrained_account(g, color):
	print_title("Enumerating Constrained account", color)
	req = g.run("""MATCH (u:User) 
		WHERE u.allowedtodelegate <> "null" 
		RETURN u.name,u.enabled,u.admincount,u.allowedtodelegate
		ORDER BY u.enabled DESC,u.name""").to_table()
	if not req:
		print('[-] No entries found')
	for u in req:
		if u[1] == False:
			pprint(f"[+] Constrained user (disabled) \t: {u[0]}", color, bcolors.CGREY, end="")
		if u[1] == True:
			pprint(f"[+] Constrained user (enabled) \t: {u[0]}", color, bcolors.LIGHTGREEN, end="")
		if u[2] == True:
			pprint(" [AdminCount]", color, bcolors.YELLOW2, end="")
		if u[3] != "null":
			pprint(f" {u[3]}", color, bcolors.MAGNETA, end="")
		print("")
	print("")


def enum_unconstrained_computer(g, color):
	print_title("Enumerating Unconstrained computer", color)
	req = g.run("""MATCH (u:Computer) 
		WHERE u.unconstraineddelegation = TRUE 
		RETURN u.name,u.enabled,u.operatingsystem
		ORDER BY u.enabled DESC,u.name""").to_table()
	if not req:
		print('[-] No entries found')
	for u in req:
		if u[1] == False:
			pprint("[+] Unconstrained computer (disabled) \t: {}".format(u[0]), color, bcolors.CGREY, end="")
		if u[1] == True:
			pprint("[+] Unconstrained computer (enabled) \t: {}".format(u[0]), color, bcolors.LIGHTGREEN, end="")
		if u[2]:
			pprint(" [{}]".format(u[2]),color, bcolors.BLUE, end="")
		print("")
	print("")

def get_comp_localadmin(g, color):
	print_title("Find all computer accounts that have local admin rights (SpoolSample+Relay)", color)
	req = g.run("MATCH p=(m:Computer)-[r:AdminTo]->(n:Computer) RETURN p")

	if not req:
		print('[-] No entries found')
	for u in req:
		# TODO: Fix output
		print(u)

def get_users(g, color, years=10):
	count = stats_return_count(f"MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - ({years} * 365 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] AND u.enabled = TRUE RETURN count(u)")
	print_title(f"Password not changed > {years} y (Total: {count} users)", color)
	req = g.run(f"""MATCH (u:User) 
		WHERE u.pwdlastset < (datetime().epochseconds - ({years} * 365 * 86400)) 
		and NOT u.pwdlastset IN [-1.0, 0.0] 
		AND u.enabled = TRUE RETURN u.name""")

	if not req:
		print('[-] No entries found')
	else:
		for u in req:
			print(u[0])

def get_gpo(g, color):
	print_title("Printing all GPOs", color)
	req = g.run("Match (n:GPO) return n").to_table()

	if not req:
		print('[-] No entries found')
	else:
		for u in req:
			obj = u[0]
			print(f"{obj['name']} - {obj['gpcpath']}")

def get_computers(g, color):
	print_title("Printing Computers with description", color)
	req = g.run("MATCH (c:Computer) WHERE c.description IS NOT NULL RETURN c.name,c.description").to_table()

	if not req:
		print('[-] No entries found')
	else:
		for c in req:
			print(f"{c[0]} - {c[1]}")

def stats(g, color):
	print_title("Stats", color)
	mytable = PrettyTable()
	mytable.field_names = ["Description","Percentage","Total"]

	ALL_USERS = stats_return_count("MATCH p=(u:User) RETURN count(*)")
	ALL_USERS_ENABLE = stats_return_count("MATCH p=(u:User) WHERE u.enabled = TRUE RETURN count(*)")
	ALL_USERS_DISABLE = stats_return_count("MATCH p=(u:User) WHERE u.enabled = FALSE RETURN count(*)")
	ALL_USERS_NOT_LOGGED_SINCE = stats_return_count("MATCH p=(u:User) WHERE u.lastlogon < (datetime().epochseconds - (180 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] and u.enabled = TRUE RETURN count(u)")
	PWD_SINCE_1_YEAR = stats_return_count("MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (1 * 365 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] AND u.enabled = TRUE RETURN count(u)")
	PWD_SINCE_2_YEAR = stats_return_count("MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (2 * 365 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] AND u.enabled = TRUE RETURN count(u)")
	PWD_SINCE_5_YEAR = stats_return_count("MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (5 * 365 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] AND u.enabled = TRUE RETURN count(u)")
	PWD_SINCE_10_YEAR = stats_return_count("MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (10 * 365 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] AND u.enabled = TRUE RETURN count(u)")
	ALL_USERS_SPN = stats_return_count("MATCH p=(u:User) WHERE u.hasspn = TRUE RETURN count(*)")
	ALL_USERS_ASREPROAST = stats_return_count("MATCH p=(u:User) WHERE u.dontreqpreauth = TRUE RETURN count(*)")
	ALL_USERS_DOM_ADM = stats_return_count("""MATCH p=(n:Group)<-[:MemberOf*1..]-(m) WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)"  AND m:User RETURN count(DISTINCT m)""")
	ALL_USER_NEVER_LOG_ENABLE = stats_return_count("MATCH (u:User) WHERE u.lastlogontimestamp =-1.0 AND u.enabled=TRUE RETURN count(u)")

	mytable.add_row(["All users","N/A", ALL_USERS])
	mytable.add_row(["All users (enabed)",round(ALL_USERS_ENABLE * 100 / ALL_USERS,2), ALL_USERS_ENABLE])
	mytable.add_row(["All users (disabled)",round(ALL_USERS_DISABLE * 100 / ALL_USERS,2), ALL_USERS_DISABLE])
	mytable.add_row(["Users with 'domain admins' rights",round(ALL_USERS_DOM_ADM * 100 / ALL_USERS_ENABLE,2),ALL_USERS_DOM_ADM])
	mytable.add_row(["Not logged (all) since 6 months",round(ALL_USERS_NOT_LOGGED_SINCE * 100 / ALL_USERS,2), ALL_USERS_NOT_LOGGED_SINCE])
	mytable.add_row(["Not logged (enabled) since 6 months",round(ALL_USERS_NOT_LOGGED_SINCE * 100 / ALL_USERS_ENABLE,2), ALL_USERS_NOT_LOGGED_SINCE])
	mytable.add_row(["Password not changed > 1 y (enabled only)",round(PWD_SINCE_1_YEAR * 100 / ALL_USERS_ENABLE,2), PWD_SINCE_1_YEAR])
	mytable.add_row(["Password not changed > 2 y (enabled only)",round(PWD_SINCE_2_YEAR * 100 / ALL_USERS_ENABLE,2), PWD_SINCE_2_YEAR])
	mytable.add_row(["Password not changed > 5 y (enabled only)",round(PWD_SINCE_5_YEAR * 100 / ALL_USERS_ENABLE,2), PWD_SINCE_5_YEAR])
	mytable.add_row(["Password not changed > 10 y (enabled only)",round(PWD_SINCE_10_YEAR * 100 / ALL_USERS_ENABLE,2), PWD_SINCE_10_YEAR])
	mytable.add_row(["Users with SPN",round(ALL_USERS_SPN * 100 / ALL_USERS_ENABLE,2), ALL_USERS_SPN])
	mytable.add_row(["Users with AS REP ROAST",round(ALL_USERS_ASREPROAST * 100 / ALL_USERS_ENABLE,2), ALL_USERS_ASREPROAST])
	mytable.add_row(["Users enabled and has never log",round(ALL_USER_NEVER_LOG_ENABLE * 100 / ALL_USERS_ENABLE,2), ALL_USER_NEVER_LOG_ENABLE])
	print(mytable)

if __name__ == "__main__":
	args = args()
	try:
		g = Graph(args.bolt, auth=(args.username, args.password))
	except Exception as e:
		print(e)
		exit(0)	

	color = args.color

	if args.years:
		get_users(g, color, years=args.years)
	elif args.ladmin:
		get_comp_localadmin(g, color)
	elif args.gpo:
		get_gpo(g, color)
	elif args.computer:
		get_computers(g, color)
	else:
		enum_DA(g, color)
		enum_priv_SPN(g, color)
		enum_priv_AS_REP_ROAST(g, color)
		enum_all_SPN(g, color)
		enum_asrep_roast(g, color)
		enum_unconstrained_account(g, color)
		enum_constrained_account(g, color)
		enum_unconstrained_computer(g, color)
		stats(g, color)
