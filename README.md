# llr_wrapper
BOINC wrapper for LLR

The wrapper requires the following files as input:

* Ini file
 - called "llr.ini" (set to be writeable)

* LLR input file
 - called "llr.in"

* LLR binary
 - called "primegrid_cllr.exe" on Windows
 - called "primegrid_llr" on Mac & Linux

LLR is executed as a child process using (Linux/Mac):

* execl() - "primegrid_llr -v" - to get the version number
* execl() - "primegrid_llr -d llr.in" - to perform the test

and on Windows:

* CreateProcess() "primegrid_cllr.exe -v" - to get the version number
* CreateProcess() "primegrid_cllr.exe -d llr.in" - to perform the test

Periodically, poll LLR for status.  Read the FFT info and the progress string from the stdout of LLR.
FFT info is echoed into the stderr file.

Once LLR has finished, read the results:

* lresults.txt
 - strip out any progress messages "*Bit*" and save to lresults_parsed.txt
 - convert to DOS line endings and save to lresults_parsed.txt.dos (Linux/Mac only)
 - Finally, boinc_copy() to "llr.out"

