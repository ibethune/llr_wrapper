// BOINC wrapper for running the LLR application
// Based on an old version of the wrapper developed
// by Andrew J. Younge and provided by BOINC
// See http://boinc.berkeley.edu/trac/wiki/WrapperApp for details
// Copyright (C) 2005 University of California
// Licensed under the GNU Lesser General Public License
// http://www.gnu.org/copyleft/lesser.html

// wrapper.C

// Current version modified by Iain Bethune
// iain@pyramid-productions.net

// Previous contributions by Mike Goetz, Rytis Slatkevicius, and others...

// System headers needed in all cases
#include <iostream>
#include <string>

#ifdef _WIN32
    // Windows-only headers
    #include "boinc_win.h"
    #include "win_util.h" // for suspend_resume()
    typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
#else
    // Linux/Mac headers
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/wait.h>
    #include <fstream>
    #include <sys/resource.h>
    #include <sys/times.h>
#endif

// BOINC includes
#include "boinc_api.h"
#include "diagnostics.h"
#include "filesys.h"
#include "util.h"
#include "error_numbers.h" 
#include "version.h" 

#ifndef BITNESS
#error "BITNESS must be defined e.g. 64 or 32"
#endif

#ifndef WRAPPER_VERSION
#error "WRAPPER_VERSION must be defined e.g. 7.00"
#endif
#define STR(X) STR2(X)
#define STR2(X) #X

#define POLL_PERIOD 1.0
#define TRICKLE_PERIOD 86400.0 // 24 hours
#define TRICKLE_FILE "trickle.dat"

#define TEST_TYPE_MAX_LENGTH 9
#define TEST_TYPE_PRP "PRP"
#define TEST_TYPE_PRIMALITY "Primality"

#define ERR_VERSION_CHECK -99

#define LINE_LENGTH 80

// The name of the executable that does the actual work:
#ifdef _WIN32
    const std::string llr_app_name = "primegrid_cllr.exe";
#else
    const std::string llr_app_name = "primegrid_llr";
#endif

// File names and arguments
const std::string llr_ini_file_name = "llr.ini";
const std::string llr_in_file_name = "llr.in";
const std::string wrapper_in_file_name = "wrapper.in";
const std::string out_file_name = "llr.out";
const std::string llr_verbose = "-d";
const std::string llr_print_version = "-v";
const std::string llr_forcePRP = "-oForcePRP=1";
const std::string llr_results = "lresults.txt";
const std::string llr_results_parsed = "lresults_parsed.txt";
#ifndef _WIN32
const std::string llr_results_parsed_dos = "lresults_parsed.txt.dos";
#endif

struct TASK
{
    double progress;
    double old_progress;
    double old_time;
    double old_checkpoint_time;
    time_t last_trickle;
    bool bGotFFT;
    bool app_suspended;
#ifdef _WIN32
    HANDLE pid_handle;
    DWORD pid;
    HANDLE hOutputReadTmp, hOutputRead, hOutputWrite;
#else
    int pid;
    int fdOutputRead;
#endif

    TASK() : progress(0.0),
             old_progress(0.0), old_time(0.0), old_checkpoint_time(0.0),
             last_trickle(time(NULL)),
#ifdef _WIN32
             pid_handle(0),
#endif
             pid(0), bGotFFT(false), app_suspended (false) {}

    bool poll(int& status);
    int run();
    void terminate();
    void kill();
    void suspend();
    void resume();
    double cpu_time();
    double read_status();
    void poll_boinc_messages();
    void send_status_message(double checkpoint_period);
    void trickle_up_progress();
};

int TASK::run()
{
    int retval;
    bool forcePRP = false;

    // First we check for a wrapper input file

    std::string wrapper_in_file;
    boinc_resolve_filename_s(wrapper_in_file_name.c_str(), wrapper_in_file);

    int llr_version_req = 0, llr_major_req = 0, llr_minor_req = 0;

    FILE *w_in = boinc_fopen(wrapper_in_file.c_str(), "r");
    if (w_in)
    {
        char line[LINE_LENGTH], test_type[TEST_TYPE_MAX_LENGTH+1];
        int wrapper_major_req, wrapper_minor_req;

        std::cerr << "A " << wrapper_in_file_name << " file was found" << std::endl;
        // Read the control line from the wrapper input
        if (fgets(line, LINE_LENGTH, w_in) != NULL &&
            sscanf(line,"%d.%d %d.%d.%d %s", &wrapper_major_req, &wrapper_minor_req, &llr_version_req, &llr_major_req, &llr_minor_req, test_type) == 6)
        {
           std::cerr << "Req wrapper version: " << wrapper_major_req << "." << wrapper_minor_req << std::endl;
           int wrapper_major, wrapper_minor;
           if (sscanf(STR(WRAPPER_VERSION),"%d.%d", &wrapper_major, &wrapper_minor) == 2)
           {
               std::cerr << "Found wrapper version: " << wrapper_major << "." << wrapper_minor << std::endl;
               if (wrapper_major_req > wrapper_major || (wrapper_major_req == wrapper_major && wrapper_minor_req > wrapper_minor))
               {
                   std::cerr << "A newer version of the LLR wrapper is required!" << std::endl;
                   fclose(w_in);
                   return ERR_VERSION_CHECK;
               }
           }
           else
           {
               std::cerr << "Failed to determine the wrapper version" << std::endl;
               fclose(w_in);
               return ERR_VERSION_CHECK;
           }

           std::cerr << "Test type: " << test_type << std::endl;
           if (strncmp(test_type, TEST_TYPE_PRP, TEST_TYPE_MAX_LENGTH) == 0)
           {
              std::cerr << "PRP test requested" << std::endl;
              forcePRP = true;
           }
           else if (strncmp(test_type, TEST_TYPE_PRIMALITY, TEST_TYPE_MAX_LENGTH) == 0)
           {
              std::cerr << "Primality test requested" << std::endl;
           }
           else
           {
              std::cerr << "Could not parse test type, proceeding with a primality test..." << std::endl;
           }
        }
        else
        {
           std::cerr << "Error reading from " << wrapper_in_file_name << std::endl;
           fclose(w_in);
           return ERR_READ;
        }

        // Copy the following two lines to the LLR input file
        FILE *l_in = boinc_fopen(llr_in_file_name.c_str(), "w");

        fgets(line, sizeof(line),w_in);
        fputs(line, l_in);
        fgets(line, sizeof(line),w_in);
        fputs(line, l_in);

        fclose(l_in);
        fclose(w_in);
    }
    else
    {
        std::cerr << "No " << wrapper_in_file_name << " file was found, continue with legacy behaviour" << std::endl;
    }

    // Run LLR to get the version number

    char buf[256];

#ifdef _WIN32
    DWORD len;

    // llr.ini MUST be writeable, so explicitly remove the read-only bit
    // a read-only llr.ini might be the cause of the "3 second error"
    if (SetFileAttributes(llr_ini_file_name.c_str(), FILE_ATTRIBUTE_NORMAL)  == 0)
        std::cerr << "Removing Read-Only from " << llr_ini_file_name << " FAILED!" << std::endl;

    std::string command_line = llr_app_name + " " + llr_print_version;
    std::replace(command_line.begin(), command_line.end(), '/', '\\');

    PROCESS_INFORMATION process_info;
    STARTUPINFO startup_info;
    SECURITY_ATTRIBUTES sa;

    sa.nLength= sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    // Create a pipe to read from the child process
    if (!CreatePipe(&hOutputReadTmp,&hOutputWrite,&sa,0))
    {
        std::cerr << "Failed to create pipe" << std::endl;
        return 250; // 250: Failed to create pipe
    }
    if (!DuplicateHandle(GetCurrentProcess(),hOutputReadTmp,
                           GetCurrentProcess(),
                           &hOutputRead, // Address of new handle.
                           0,FALSE, // Make it uninheritable.
                           DUPLICATE_SAME_ACCESS))
    {
        std::cerr << "Failed to DuplicateHandle()" << std::endl;
        return 251;
    }

    memset(&process_info, 0, sizeof(process_info));
    memset(&startup_info, 0, sizeof(startup_info));

    // pass handles to app
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdError = hOutputWrite;
    startup_info.hStdOutput = hOutputWrite;

    if (!CreateProcess(llr_app_name.c_str(),
        (LPSTR)command_line.c_str(),
        NULL,
        NULL,
        true, // inherit handles
        CREATE_NO_WINDOW|IDLE_PRIORITY_CLASS,
        NULL,
        NULL,
        &startup_info,
        &process_info
        ))
        {
            std::cerr << "Invocation of CreateProcess( " << llr_app_name << " ) FAILED!" << std::endl;
            return ERR_EXEC;
        }

    // Wait for LLR to exit

    WaitForSingleObject( process_info.hProcess, INFINITE );
    CloseHandle( process_info.hProcess );
    CloseHandle( process_info.hThread );

    if(ReadFile(hOutputRead, buf, sizeof(buf)-1, &len, NULL))
    {
        buf[len] = '\0';
        std::cerr << buf << std::endl; 
    }
    else
    {
        std::cerr << "Error reading the LLR version number, continuing..." << std::endl;
    }
#else
    int len, fd_out[2];

    if (pipe(fd_out) < 0)
    {
        std::cerr << "Failed to create pipe" << std::endl;
        return 250; // 250: Failed to create pipe
    }

    pid = fork();
    if (pid == -1)
    {
        boinc_finish(ERR_FORK);
    }
    if (pid == 0)
    {
        // we're in the child process here
        close(fd_out[0]);
        dup2(fd_out[1],STDOUT_FILENO);
        retval = execl(llr_app_name.c_str(), llr_app_name.c_str(), llr_print_version.c_str(), NULL);

        // If execl failed for some reason
        // wait 5 seconds then try again,
        // A second failure is fatal
        std::cerr << "execl failed once: " << strerror(errno) << std::endl;
        boinc_sleep(5.0);
        retval = execl(llr_app_name.c_str(), llr_app_name.c_str(), llr_print_version.c_str(), NULL);
        
        std::cerr << "execl failed twice: " << strerror(errno) << std::endl;
        exit(ERR_EXEC);
    }
    else
    {
        // In the parent process
        int status;

        // Wait for LLR to exit
        waitpid(pid, &status, WUNTRACED);

        close(fd_out[1]);
        /* Prevent parent read() blocking on child output pipe. */
        fcntl(fd_out[0],F_SETFL,fcntl(fd_out[0],F_GETFL)|O_NONBLOCK);

        if ((len = read(fd_out[0],buf,sizeof(buf)-1)) > 0)
        {
          buf[len] = '\0';
        }
        else
        {
            std::cerr << "Error reading the LLR version number, continuing..." << std::endl;
        }
    }
#endif

    std::cerr << "Req LLR version: " << llr_version_req << "." << llr_major_req << "." << llr_minor_req << std::endl;

    if (llr_version_req != 0 || llr_major_req !=0 || llr_minor_req != 0)
    {
        int llr_version, llr_major, llr_minor;
        // buf contains a null-terminated LLR version string (assumed to always be in this format)
        if (sscanf(buf,"LLR Program - Version %d.%d.%d", &llr_version, &llr_major, &llr_minor) != 3)
        {
             std::cerr << "Error parsing the LLR version string!" << std::endl;
             return ERR_VERSION_CHECK;
        }

        // A version number was specified in the wrapper.in, so check it
        std::cerr << "Found LLR version: " << llr_version << "." << llr_major << "." << llr_minor << std::endl;
        if (llr_version_req > llr_version ||
           (llr_version_req == llr_version && llr_major_req > llr_major ) ||
           (llr_version_req == llr_version && llr_major_req == llr_major && llr_minor_req > llr_minor))
        {
             std::cerr << "A newer version of LLR is required!" << std::endl;
             return ERR_VERSION_CHECK;
        }
    }

    // Now run LLR again to perform the test

    std::string llr_in_file;
    boinc_resolve_filename_s(llr_in_file_name.c_str(), llr_in_file);
#ifdef __WIN32
    if (forcePRP)
    {
       command_line = llr_app_name + " " + llr_verbose + " " + llr_forcePRP + " " + llr_in_file;
    }
    else
    {
       command_line = llr_app_name + " " + llr_verbose + " " + llr_in_file;
    }
    std::replace(command_line.begin(), command_line.end(), '/', '\\');

    memset(&process_info, 0, sizeof(process_info));
    memset(&startup_info, 0, sizeof(startup_info));

    // pass handles to app
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdError = hOutputWrite;
    startup_info.hStdOutput = hOutputWrite;

    if (!CreateProcess(llr_app_name.c_str(),
        (LPSTR)command_line.c_str(),
        NULL,
        NULL,
        true, // inherit handles
        CREATE_NO_WINDOW|IDLE_PRIORITY_CLASS,
        NULL,
        NULL,
        &startup_info,
        &process_info
        ))
        {
            std::cerr << "Invocation of CreateProcess( " << llr_app_name << " ) FAILED!" << std::endl;
            return ERR_EXEC;
        }

    pid_handle = process_info.hProcess;
    pid = process_info.dwProcessId;
    HANDLE thread_handle = process_info.hThread;
    SetThreadPriority(thread_handle, THREAD_PRIORITY_IDLE);

#else

    if (pipe(fd_out) < 0)
    {
        std::cerr << "Failed to create pipe" << std::endl;
        return 250; // 250: Failed to create pipe
    }

    pid = fork();
    if (pid == -1)
    {
        boinc_finish(ERR_FORK);
    }
    if (pid == 0)
    {
        // we're in the child process here
        close(fd_out[0]);
        dup2(fd_out[1],STDOUT_FILENO);
        setpriority(PRIO_PROCESS, 0, PROCESS_IDLE_PRIORITY);
        if (forcePRP)
        {
            retval = execl(llr_app_name.c_str(), llr_app_name.c_str(), llr_verbose.c_str(), llr_forcePRP.c_str(), llr_in_file.c_str(), NULL);

        }
        else
        {
            retval = execl(llr_app_name.c_str(), llr_app_name.c_str(), llr_verbose.c_str(), llr_in_file.c_str(), NULL);
        }

        // If execl failed for some reason
        // wait 5 seconds then try again,
        // A second failure is fatal
        std::cerr << "execl failed once: " << strerror(errno) << std::endl;
        boinc_sleep(5.0);
        retval = execl(llr_app_name.c_str(), llr_app_name.c_str(), llr_verbose.c_str(), NULL);

        std::cerr << "execl failed twice: " << strerror(errno) << std::endl;
        exit(ERR_EXEC);
    }
    else
    {
        // In the parent process
        close(fd_out[1]);
        /* Prevent parent read() blocking on child output pipe. */
        fcntl(fd_out[0],F_SETFL,fcntl(fd_out[0],F_GETFL)|O_NONBLOCK);
        fdOutputRead = fd_out[0];
    }

#endif

    app_suspended = false;
    return 0;
}

bool TASK::poll(int& status)
{
#ifdef _WIN32
    unsigned long exit_code;
    if (GetExitCodeProcess(pid_handle, &exit_code)) {
        if (exit_code != STILL_ACTIVE) {
            status = exit_code;
            return true;
        }
    }
#else
    int wpid;
    struct rusage ru;
    wpid = wait4(pid, &status, WNOHANG, &ru);
    if (wpid) return true;
#endif
    return false;
}

void TASK::kill()
{
#ifdef _WIN32
    TerminateProcess(pid_handle, -1);
#else
    // Send a KILL, LLR terminates ASAP
    ::kill(pid, SIGKILL);
#endif
}

void TASK::terminate()
{
#ifdef _WIN32
    TerminateProcess(pid_handle, -1);
#else
    // Send a TERM, then wait until LLR checkpoints and terminates
    ::kill(pid, SIGTERM);
    int status;
    waitpid(pid, &status, WUNTRACED);
#endif
}

void TASK::suspend()
{
#ifdef _WIN32
    suspend_or_resume_threads(pid, 0, false);
#else
    ::kill(pid, SIGSTOP);
#endif
}

void TASK::resume()
{
#ifdef _WIN32
    suspend_or_resume_threads(pid, 0, true);
#else
    ::kill(pid, SIGCONT);
#endif
}

void TASK::poll_boinc_messages()
{
    BOINC_STATUS status;
    boinc_get_status(&status);
    if (status.no_heartbeat)
    {
        terminate();
        exit(0);
    }
    if (status.quit_request)
    {
        terminate();
        exit(0);
    }
    if (status.abort_request)
    {
        kill();
        exit(0);
    }
    if (status.suspended)
    {
        if (!app_suspended)
        {
            suspend();
            app_suspended = true;
        }
    }
    else
    {
        if (app_suspended)
        {
            resume();
            app_suspended = false;
        }
    }
}

double TASK::cpu_time()
{
#ifdef _WIN32
    double cpu;
    OSVERSIONINFOEX osvi;
    SYSTEM_INFO si;
    PGNSI pGNSI;
    BOOL bOsVersionInfoEx;

    ZeroMemory(&si, sizeof(SYSTEM_INFO));
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

    // Try calling GetVersionEx using the OSVERSIONINFOEX structure.
    // If that fails, try using the OSVERSIONINFO structure.
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) ) {
        osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
        if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) )
            return FALSE;
    }

    // Call GetNativeSystemInfo if supported or GetSystemInfo otherwise.
    pGNSI = (PGNSI) GetProcAddress(
        GetModuleHandle(TEXT("kernel32.dll")),
        "GetNativeSystemInfo");
    if (NULL != pGNSI) {
        pGNSI(&si);
    } else {
        GetSystemInfo(&si);
    }

    switch (osvi.dwPlatformId) {
        case VER_PLATFORM_WIN32_NT:
            FILETIME creation_time, exit_time, kernel_time, user_time;
            ULARGE_INTEGER tKernel, tUser;
            LONGLONG totTime;

            GetProcessTimes(
                pid_handle, &creation_time, &exit_time, &kernel_time, &user_time
            );

            tKernel.LowPart = kernel_time.dwLowDateTime;
            tKernel.HighPart = kernel_time.dwHighDateTime;
            tUser.LowPart = user_time.dwLowDateTime;
            tUser.HighPart = user_time.dwHighDateTime;
            totTime = tKernel.QuadPart + tUser.QuadPart;

            cpu = totTime / 1.e7;
            return cpu;
            break;
        case VER_PLATFORM_WIN32_WINDOWS:
            cpu = 3600; // Better than nothing...
            return cpu;
            break;
    }
    return 0;
#elif defined(__linux__)
    struct tms t;
    FILE *f;
    char fn[32];
    unsigned long ut, st;
    clock_t ticks = 0;

    /* Add CPU times used by parent and completed children */
    if (times(&t) != (clock_t)-1)
      ticks += (t.tms_utime + t.tms_stime + t.tms_cutime + t.tms_cstime);

    /* Add CPU times used by incomplete children */
    sprintf(fn,"/proc/%d/stat",pid);
    if ((f = fopen(fn,"r")) != NULL)
    {
      if (fscanf(f,"%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%lu%lu",&ut,&st)==2)
        ticks += (ut + st);
      fclose(f);
    }

    /* CLK_TCK should be defined in <sys/times.h>, but it goes missing when
       compiling C++. */
#ifndef CLK_TCK
# define CLK_TCK ((clock_t)sysconf(_SC_CLK_TCK))
#endif

    return (double)ticks/CLK_TCK;
#else
    static double t=0, cpu;
    if (t) {
        double now = dtime();
        cpu += now-t;
        t = now;
    } else {
        t = dtime();
    }
    return cpu;
#endif
}


double TASK::read_status()
{
    char buf[256];
    for (;;)
    {
#ifdef _WIN32
        DWORD child_stdout = 0;
        if (!::PeekNamedPipe(hOutputRead, NULL, 0, NULL,&child_stdout, NULL))
        // break loop, child process terminated
            break;
        if (!child_stdout) 
        // no data available from child, return old_progress(?)...
            return old_progress;
        DWORD len;
        if (ReadFile(hOutputRead, buf, sizeof(buf)-1, &len, NULL))
#else
        ssize_t len;
        if ((len = read(fdOutputRead,buf,sizeof(buf)-1)) > 0)
#endif
        {
            const char *fft_key[] = {"Using"};
            const char *iter_key[] = {"iteration :", "bit:", "Iter:", "Bit:"};
            char *str,*end;
            char *line;
            size_t i;
            char ch;
            int x, y;

            buf[len] = '\0';

            if (bGotFFT == false)
            {
                for (i = 0; i < sizeof(fft_key)/sizeof(fft_key[0]); i++)
                {
                    if ((str = strstr(buf,fft_key[i])) != NULL)
                    {
                        end = str;
                        // Find the next new line or carriage return
                        while (*end != '\0' && *end != '\r' && *end != '\n') end++;
                        *end = '\0';

                        std::cerr << str << std::endl;
                        bGotFFT = true;
                        break;
                    }
                }
            }

            for (i = 0; i < sizeof(iter_key)/sizeof(iter_key[0]); i++)
            {
                if (((str = strstr(buf,iter_key[i])) != NULL) &&
                    (sscanf(str+strlen(iter_key[i])," %d / %d%c",&x,&y,&ch) == 3) &&
                    (y > 0))
                {
                    return (double)x/y;
                }
            }
        }
#ifndef _WIN32
        // Mac and Linux don't loop back
        break;
#endif
    }
    return -1.0;
}

void TASK::send_status_message(double checkpoint_period)
{
    double new_checkpoint_time = old_checkpoint_time;
    double cputime = cpu_time();

    old_progress = progress;
    progress = read_status();
    new_checkpoint_time = cputime + old_time;
    if (progress > old_progress)
        old_checkpoint_time = new_checkpoint_time;

    if (progress < 0)
        progress = old_progress;

    boinc_report_app_status(
        cputime + old_time,
        old_checkpoint_time,
        progress
    );
    boinc_fraction_done(progress);
}

void TASK::trickle_up_progress()
{
    time_t now = time(NULL);

    // If the time since the last trickle is long enough, and we have valid progress to report
    if (difftime(now, last_trickle) > TRICKLE_PERIOD && progress != 0.0)
    {
        // Send progress via a trickle-up message
        last_trickle = now;

        double progress = boinc_get_fraction_done();
        double cpu;
        boinc_wu_cpu_time(cpu); // Only from previous runs, since we don't checkpoint
        cpu += cpu_time();
        APP_INIT_DATA init_data;
        boinc_get_init_data(init_data);
        double run = boinc_elapsed_time() + init_data.starting_elapsed_time;

        char msg[512];
        sprintf(msg, "<trickle_up>\n"
                    "   <progress>%f</progress>\n"
                    "   <cputime>%f</cputime>\n"
                    "   <runtime>%f</runtime>\n"
                    "</trickle_up>\n",
                     progress, cpu, run  );
        char variety[64];
        sprintf(variety, "llr_progress");
        int ret = boinc_send_trickle_up(variety, msg);

        // Store the last_trickle timestamp to a file, so we can recover it when we restart.
        FILE *f = boinc_fopen(TRICKLE_FILE, "wb"); // overwrite
        if (f)
        {
            fwrite(&last_trickle, sizeof(time_t), 1, f);
            fclose(f);
        }
    }
}

#ifndef _WIN32
bool unix2dos(const std::string& in, const std::string& out)
{
    std::ifstream in_file(in.c_str());
    std::ofstream out_file(out.c_str());

    if ((!in_file) || (!out_file))
        return false;

    std::string buffer;
    while (std::getline(in_file, buffer))
        out_file << buffer << "\r\n";

    out_file << std::flush;
    out_file.close();
    return true;
}
#endif


int main(int argc, char** argv)
{
    BOINC_OPTIONS options;
    int retval;

#ifndef _WIN32
    // Close good amount of possibly opened (inherited) handles except standard 0-2
    // (stdin, stdout, stderr) to avoid handle-inheritance-on-exec bug in older Boinc clients
    // https://github.com/BOINC/boinc/issues/1388
    for (int i = 3; i < 100; i++)
    {
        close(i);
    }
#endif

    boinc_init_diagnostics(
        BOINC_DIAG_DUMPCALLSTACKENABLED |
        BOINC_DIAG_HEAPCHECKENABLED |
        BOINC_DIAG_TRACETOSTDERR |
        BOINC_DIAG_REDIRECTSTDERR
    );

    memset(&options, 0, sizeof(options));
    options.main_program = true;
    options.check_heartbeat = true;
    options.handle_process_control = true;
#if BOINC_MAJOR_VERSION < 7 || (BOINC_MAJOR_VERSION == 7 && BOINC_MINOR_VERSION < 5)
    options.handle_trickle_ups = true;
#endif

    std::cerr << "BOINC llr wrapper (version " << STR(WRAPPER_VERSION) << ")" << std::endl;
    std::cerr << "Using Jean Penne's llr (" << BITNESS << " bit)" << std::endl;

    boinc_init_options (&options);

    APP_INIT_DATA uc_aid;
    boinc_get_init_data(uc_aid);
    if (uc_aid.checkpoint_period < 1.0)
        uc_aid.checkpoint_period = 60.0;

    // Start application
    TASK t;
    boinc_wu_cpu_time(t.old_time);
    t.old_checkpoint_time = t.old_time;

    retval = t.run();
    if (retval)
    {
        std::cerr << "Can't run app: " << llr_app_name << " (Error code: " << retval << ")" << std::endl;
        boinc_finish(retval);
    }

    // Attempt to read the last trickle timestamp from file
    bool got_trickle = false;
    FILE *f = boinc_fopen(TRICKLE_FILE, "rb");
    if (f)
    {
        time_t last_trickle_read;
        if (fread(&last_trickle_read, sizeof(time_t), 1, f) == 1)
        {
            t.last_trickle = last_trickle_read;
            got_trickle = true;
        }
        fclose(f);
    }

    // If we couldn't read a trickle timestamp, try to create a new one
    if (!got_trickle)
    {
        f = boinc_fopen(TRICKLE_FILE, "wb"); // overwrite
        if (f)
        {
            fwrite(&(t.last_trickle), sizeof(time_t), 1, f);
            fclose(f);
        }
    }

    // Poll for application status
    int status;
    for(;;)
    {
        if (t.poll(status))
        {
#ifndef _WIN32
            int child_ret_val = WEXITSTATUS(status);
            if (child_ret_val)
            {
                std::cerr << "app error: " <<  status << std::endl;
                boinc_finish(status);
            }
#endif
            break;
        }
        t.poll_boinc_messages();
        t.send_status_message(uc_aid.checkpoint_period);
        t.trickle_up_progress();
        boinc_sleep(POLL_PERIOD);
    }

    // LLR exited successfully
    // Parse output file to remove checkpoint messages
    std::string stri;
    char cLine[256];
    std::ifstream FR; // Read
    std::ofstream FW; // Write
    int iCount = 0;
    FR.open(llr_results.c_str());
    FW.open(llr_results_parsed.c_str());
    while ((FR.is_open()) && (!FR.eof())) {
        FR.getline(cLine, 256);
        stri = cLine;
        if (stri.rfind("Bit") == std::string::npos) {
            if (iCount > 0) {
                FW<<std::endl;
            }
            iCount++;
            FW<<cLine;
        }
    }
    FW.close();

    // Find final output file
    std::string out_file;
    retval = boinc_resolve_filename_s(out_file_name.c_str(), out_file);

    std::string llr_results_file;
#ifndef __WIN32
    //Convert line-endings:
    if (!unix2dos(llr_results_parsed.c_str(), llr_results_parsed_dos.c_str()))
    {
        std::cerr << "failed to convert line endings!" << std::endl;
        boinc_finish(-1);
        return 1;
    }
    llr_results_file = llr_results_parsed_dos;
#else
    llr_results_file = llr_results_parsed;
#endif

    // Save result file
    int retries = 5;
    do {
       retval = boinc_copy(llr_results_file.c_str(), out_file.c_str());
       retries--;
       if (retval != 0){
          std::cerr << "boinc_copy() failed (Error code: " << retval << ")" << std::endl;
          std::cerr << "Sleeping 10s then retry..." << std::endl;
          boinc_sleep(10.0);
       }
    } while (retval != 0 && retries > 0);

    // All done
    boinc_finish(status);
}
