#!/usr/bin/python3

import argparse
import subprocess
import time


results = []
normal_libfolders = ["/usr/local/lib", "/usr/local/lib64", "/usr/lib", "/usr/lib64", "/lib", "/lib64"]
suid_only = False
show_libs = False

parser = argparse.ArgumentParser(description="Slibjack: a utility to search for potentially exploitable conditions in executables for use with malicious shared libraries")
parser.add_argument("-suid", "--suidonly", help="Search only suid binaries", action="store_true")
parser.add_argument("-libs", "--showlibs", help="Show libraries loaded by the discovered executable", action="store_true")
args = parser.parse_args()

if args.suidonly:
        suid_only = True

if args.showlibs:
        show_libs = True

logo = r'''  _____ _ _ _     _            _    
 / ____| (_) |   (_)          | |   
| (___ | |_| |__  _  __ _  ___| | __
 \___ \| | | '_ \| |/ _` |/ __| |/ /
 ____) | | | |_) | | (_| | (__|   < 
|_____/|_|_|_.__/| |\__,_|\___|_|\_\
                _/ |                
               |__/   '''
print(logo)


if suid_only:
        print("[*] Searching only suid binaries")
        search_params = "-perm -u=s"
else:
        print("[*] Searching all binaries")
        search_params = "-executable"

if show_libs:
        print("[*] Showing associated libraries")
else:
        print("[*] Omitting associated libraries")


search_output = subprocess.run("find / " + search_params + " -type f 2>/dev/null", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
refined_output = search_output.stdout.decode("UTF-8")
suid_binaries = refined_output.splitlines()
print("[+] " + str(len(suid_binaries)) + " binaries discovered. Searching for potential exploitable conditions...")

for suid_bin in suid_binaries:
        readelf_out = subprocess.run("readelf -d " + suid_bin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        refined_readelf_output = readelf_out.stdout.decode("UTF-8")
        readelf_lines = refined_readelf_output.splitlines()
        for readelf_line in readelf_lines:
                if "$ORIGIN" in readelf_line:
                        rpath_parts = readelf_line.split()
                        rpath_path = rpath_parts[-1]
                        results.append("[!] ORIGIN found: " + rpath_path)
                        take_note = True
                elif (("RPATH" in readelf_line) or ("RUNPATH" in readelf_line)):
                        rpath_parts = readelf_line.split()
                        rpath_path = rpath_parts[-1]
                        if not any(substring in rpath_path for substring in normal_libfolders):
                                results.append("[!] unusual RPATH/RUNPATH found: " + rpath_path)

        if len(results) > 0:
                results.insert(0, "---\n" + suid_bin + ": ")
                if show_libs:
                        ldd_output = subprocess.run("ldd " + suid_bin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                        refined_ldd_output = ldd_output.stdout.decode("UTF-8")
                        ldd_libs = refined_ldd_output.splitlines()
                        for ldd_lib in ldd_libs:
                                ldd_pieces = ldd_lib.split()
                                lib_path = ldd_pieces[-2]
                                results.append("[+] - Library: " + ldd_lib)
                for result in results:
                        print(result)
                results.clear()
