# llr_wrapper
BOINC wrapper for LLR

The wrapper requires the following files as input:

* Ini file (contains LLR options)
 - called "llr.ini.orig", boinc_copy() to "llr.ini"

* LLR input file (contains candidate to be tested)
 - called "llr.in", boinc_copy() to "llrin.txt" 

* LLR binary
 - called "primegrid_llr_ARCH_TRIPLET.orig", where ARCH_TRIPLET could be x86_64-apple-darwin etc.
 - copied to "primegrid_llr_ARCH_TRIPLET"

LLR is then executed as a child process using:

execvp() - "primegrid_llr_ARCH_TRIPLET -d"

Periodically, poll LLR for status.  Read the FFT info and the progress string from the stdout of LLR.
FFT info is echoed into the stderr file.

Once LLR has finished, read the results:

* lresults.txt (contains a single line with the candidate, prime or composite, runtime)
 - strip out any progress messages "*Bit*" and save to lresults_parsed.txt
 - convert to DOS line endings and save to lresults_parsed.txt.dos
 - Finally, boinc_copy() to "llr.out"
