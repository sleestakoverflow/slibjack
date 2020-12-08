# Slibjack
A simple utility to search for potentially exploitable conditions in Linux executables for use with malicious shared libraries. It can search for SUID binaries specifically or all binaries. The utility will identify conditions in binaries where libraries are loaded using the $ORIGIN variable or have hardcoded RPATH/RUNPATH values.
