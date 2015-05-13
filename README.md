# llr_wrapper
BOINC wrapper for LLR

--- Linux/Mac wrapper ---

The wrapper requires the following files as input:

* Ini file (contains LLR options)
 - called "llr.ini.orig", boinc_copy() to "llr.ini"

* LLR input file (contains candidate to be tested)
 - called "llr.in", boinc_copy() to "llrin.txt" 

* LLR binary
 - called "primegrid_llr.orig"
 - copied to "primegrid_llr"

LLR is then executed as a child process using:

execvp() - "primegrid_llr -v" - to get the version number
execvp() - "primegrid_llr -d" - to perform the test

Periodically, poll LLR for status.  Read the FFT info and the progress string from the stdout of LLR.
FFT info is echoed into the stderr file.

Once LLR has finished, read the results:

* lresults.txt (contains a single line with the candidate, prime or composite, runtime)
 - strip out any progress messages "*Bit*" and save to lresults_parsed.txt
 - convert to DOS line endings and save to lresults_parsed.txt.dos
 - Finally, boinc_copy() to "llr.out"



--- Windows wrapper ---

The wrapper requires the following files as input:

* Ini file
 - called "llr.ini" (set to be writeable)

* LLR inut file
 - called "llr.in"

* LLR binary
 - called "primegrid_cllr.exe"

LLR is executed as a child process using:

"primegrid_cllr.exe -d (LLR_ARGS) llr.in" - to perform the test


Periodically, poll LLR for status, reading the FFT length and the progress string from LLR stdout.

Once LLR has finished, read the results:

* lresults.txt
 - strip out any progress messages "*Bit*" and save to lresults_parsed.txt
 - Finally, boinc_copy() to "llr.out"

