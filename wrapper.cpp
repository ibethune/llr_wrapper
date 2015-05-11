#include <stdio.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include "boinc_win.h"
#include "win_util.h" // supend_resume
typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/times.h>
#include <sys/wait.h>
#endif

#include "boinc_api.h"
#include "diagnostics.h"
#include "filesys.h"
#include "parse.h"
#include "util.h"
#include "str_util.h"
#include "error_numbers.h"

#ifdef _WIN32
# define LLR_LOCAL_EXE_FILENAME "primegrid_cllr.exe"
# define LLR_ARGS "-d" // space separated, e.g. "-d" "-x" ... 

#else
# define LLR_EXE_FILENAME  "primegrid_cllr_3.7.1c.orig"
# define LLR_LOCAL_EXE_FILENAME "primegrid_cllr_3.7.1c"
# define LLR_ARGS "-d" /* comma separated, e.g. "-d", "-x", ... */
#endif

using namespace std;

string application;
string sInputFile;
string sExeFile;
string sCommandLine;
double old_progress;
double progress;
bool bGotFFT = false;
bool app_suspended = false;
bool bReadWrite;
double oldTime = 0;
APP_INIT_DATA uc_aid;
double dPreCheckpointTime = 0;
#define STATE_FILE    "boinc_state_file.xml"
#ifdef _WIN32
HANDLE hOutputReadTmp, hOutputRead, hOutputWrite;
HANDLE hInputReadTmp, hInputRead, hInputWrite;
HANDLE pid_handle;
DWORD pid;
HANDLE thread_handle;
struct _stat last_stat;    // mod time of checkpoint file
double done_that;
#else
//int fdInputWrite;
int fdOutputRead;
int pid;
#endif


int run_application(char** argv) {
#ifdef _WIN32
    PROCESS_INFORMATION process_info;
    STARTUPINFO startup_info;
    SECURITY_ATTRIBUTES sa;
    
    sa.nLength= sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    
    if (!CreatePipe(&hOutputReadTmp,&hOutputWrite,&sa,0)) {
        fprintf(stderr, "Failed to create pipe\n");
        return 250; // 250: Failed to create pipe
    }
    if (!CreatePipe(&hInputReadTmp,&hInputWrite,&sa,0)) {
        fprintf(stderr, "Failed to create pipe\n");
        return 250; // 250: Failed to create pipe
    }
    
    if (!DuplicateHandle(GetCurrentProcess(),hOutputReadTmp,
                           GetCurrentProcess(),
                           &hOutputRead, // Address of new handle.
                           0,FALSE, // Make it uninheritable.
                           DUPLICATE_SAME_ACCESS)) {
        fprintf(stderr, "Failed to DuplicateHandle()\n");
        return 251;
    }
#else
    // int fd_in[2];
    int fd_out[2];

    // if (pipe(fd_in) < 0) {
    //   fprintf(stderr, "Failed to create pipe\n");
    //   return 250; // 250: Failed to create pipe
    // }
    if (pipe(fd_out) < 0) {
      fprintf(stderr, "Failed to create pipe\n");
      return 250; // 250: Failed to create pipe
    }
#endif
    
    boinc_resolve_filename_s(LLR_LOCAL_EXE_FILENAME, sExeFile);
    boinc_resolve_filename_s("llr.in", sInputFile);
	sCommandLine = sExeFile+std::string(" ")+std::string(LLR_ARGS)+std::string(" ")+sInputFile;
#ifdef _WIN32
	std::replace(sCommandLine.begin(), sCommandLine.end(), '/', '\\');
#endif
    
//	fprintf(stderr,"Exe: %s, Input: %s\n", sExeFile.c_str(), sInputFile.c_str());
//	fprintf(stderr,"Command line: %s\n", sCommandLine.c_str());

#ifdef _WIN32
// llr.ini MUST  be writeable, so explicitely remove the read-only bit
// a read-only llr.ini might be the cause of the "3 second error"
	if (SetFileAttributes("llr.ini", FILE_ATTRIBUTE_NORMAL)  == 0)
		fprintf(stderr,"Removing Read-Only from llr.ini FAILED!\n");

    memset(&process_info, 0, sizeof(process_info));
    memset(&startup_info, 0, sizeof(startup_info));
    
    // pass handles to app
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdError = hOutputWrite;
    startup_info.hStdOutput = hOutputWrite;
    startup_info.hStdInput = hInputWrite;
    
//	fprintf(stderr,"Invoking CreateProcess...\n");
    if (!CreateProcess(sExeFile.c_str(),
        (LPSTR)sCommandLine.c_str(),
        NULL,
        NULL,
        true, // inherit handles
        CREATE_NO_WINDOW|IDLE_PRIORITY_CLASS,
        NULL,
        NULL,
        &startup_info,
        &process_info
    )) {
		fprintf(stderr,"Invocation of CreateProcess(LLR) FAILED!\n");
        return ERR_EXEC;
    }
//	fprintf(stderr,"Invocation suceeded!\n");
    pid_handle = process_info.hProcess;
    pid = process_info.dwProcessId;
	thread_handle = process_info.hThread;
    SetThreadPriority(thread_handle, THREAD_PRIORITY_IDLE);
    

    // Get version info
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO *)&osvi);
    
    fprintf(stderr, "Major OS version: %d; Minor OS version: %d\n", osvi.dwMajorVersion, osvi.dwMinorVersion);
#else
    switch((pid = fork()))
    {
      case -1: /* fork() failed. */
        boinc_finish(ERR_FORK);
        return ERR_FORK;

      case 0: /* Child process. */
        char buf[256];
        boinc_resolve_filename(LLR_LOCAL_EXE_FILENAME,buf,sizeof(buf));
        // close(fd_in[1]);
        close(fd_out[0]);
        // dup2(fd_in[0],STDIN_FILENO);
        dup2(fd_out[1],STDOUT_FILENO);
        execl(buf,buf,LLR_ARGS,NULL);
        exit(ERR_EXEC);

      default: /* Parent process. */
        // close(fd_in[0]);
        close(fd_out[1]);
        /* Prevent parent read() blocking on child output pipe. */
        fcntl(fd_out[0],F_SETFL,fcntl(fd_out[0],F_GETFL)|O_NONBLOCK);
        // fdInputWrite = fd_in[1];
        fdOutputRead = fd_out[0];
        break;
    }
#endif

    return 0;
}

bool poll_application(int& status) {
#ifdef _WIN32
    unsigned long exit_code;
    if (GetExitCodeProcess(pid_handle, &exit_code)) {
        if (exit_code != STILL_ACTIVE) {
            status = exit_code;
            return true;
        }
    }
#else
    int wpid, stat;
    wpid = waitpid(pid, &stat, WNOHANG);
    if (wpid) {
        status = stat;
        return true;
    }
#endif
    return false;
}

void kill_app() {
    //fprintf(stderr, "Killing\n");
#ifdef _WIN32
    TerminateProcess(pid_handle, -1);
#else
    kill(pid, SIGKILL);
#endif
}

void stop_app() {
    //fprintf(stderr, "Suspending\n");
#ifdef _WIN32
	suspend_or_resume_threads(pid, 0, false);
#else
    kill(pid, SIGSTOP);
#endif
}

void resume_app() {
    //fprintf(stderr, "Resuming\r\n");
#ifdef _WIN32
   suspend_or_resume_threads(pid, 0, true);
#else
    kill(pid, SIGCONT);
#endif
}

void poll_boinc_messages() {
    BOINC_STATUS status;
    boinc_get_status(&status);
    if (status.no_heartbeat) {
        kill_app();
        exit(0);
    }
    if (status.quit_request) {
        kill_app();
        exit(0);
    }
    if (status.abort_request) {
        kill_app();
        exit(0);
    }
    if (status.suspended) {
        if (!app_suspended) {
            stop_app();
            app_suspended = true;
        }
    } else {
        if (app_suspended) {
            resume_app();
            app_suspended = false;
        }
    }
}

double cpu_time() {
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

double read_status(void) {
 CHAR buf[256];
  DWORD len;
for (;;)
    {
DWORD child_stdout = 0;
if (!::PeekNamedPipe(hOutputRead, NULL, 0, NULL,&child_stdout, NULL))    // break loop, child process terminated
      break;
if (!child_stdout)           // no data available from child, return old_progress(?)...
     return old_progress;

if(ReadFile(hOutputRead, buf, sizeof(buf)-1, &len, NULL)) 
{
    const char *fft_key[] = {"Used fftlen =", "FFT length"};
    const char *iter_key[] = {"iteration :", "bit:", "Iter:", "Bit:"};
    const char *str;
    size_t i;
    char ch;
    int x, y;

    buf[len] = '\0';
    if (bGotFFT == false)
      for (i = 0; i < sizeof(fft_key)/sizeof(fft_key[0]); i++)
        if ((str = strstr(buf,fft_key[i])) != NULL)
          if (sscanf(str+strlen(fft_key[i])," %d%c",&x,&ch) == 2)
          {
            fprintf(stderr,"FFT length: %d%c\n",x,(ch=='K' || ch=='M')?ch:' ');
            bGotFFT = true;
            break;
		  }
    for (i = 0; i < sizeof(iter_key)/sizeof(iter_key[0]); i++)
      if ((str = strstr(buf,iter_key[i])) != NULL)
        if (sscanf(str+strlen(iter_key[i])," %d / %d%c",&x,&y,&ch) == 3)
          if (y > 0)
            return (double)x/y;
}

  return -1.0;
}
}

void send_status_message() {
    double cputime = cpu_time();
    double progress = read_status();

    if (progress < 0)
      progress = old_progress;
    else
      old_progress = progress;

    if (boinc_time_to_checkpoint()) {
        dPreCheckpointTime = cputime + oldTime;
        boinc_checkpoint_completed();
    }
    boinc_report_app_status(cputime + oldTime, dPreCheckpointTime, progress);
}

int main(int argc, char** argv) {
    BOINC_OPTIONS options;
    int retval;
    
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
    options.backwards_compatible_graphics = true;
    
    fprintf(stderr, "BOINC LLR 6.07 wrapper: starting\r\n");
    boinc_init_options(&options);
    boinc_get_init_data(uc_aid);
	boinc_wu_cpu_time(oldTime);
	progress = boinc_get_fraction_done();
    dPreCheckpointTime = oldTime;
 	retval = run_application(argv);
    if (retval) {
        fprintf(stderr, "Can't run app: %d\r\n", retval);
        boinc_finish(retval);
    }
    while(1) {
        int status;
        
        if (poll_application(status)) {
            // Parse output file to remove checkpoint messages
            string stri;
            char cLine[256];
            ifstream FR; // Read
            ofstream FW; // Write
            //int iSignPos = -1;
            int iCount = 0;
            FR.open("lresults.txt");
            FW.open("lresults_parsed.txt");
            while ((FR.is_open()) && (!FR.eof())) {
                FR.getline(cLine, 256);
                stri = cLine;
                if (stri.rfind("Bit") == string::npos) {
                    if (iCount > 0) {
                        FW<<endl;
                    }
                    iCount++;
                    FW<<cLine;
                }
            }
            FW.close();
            
            boinc_resolve_filename_s("llr.out", sInputFile);
            boinc_copy("lresults_parsed.txt", sInputFile.c_str());
            send_status_message();
            fprintf(stderr, "All done!\n");
            boinc_finish(status);
        } else {
            boinc_sleep(1.);
            poll_boinc_messages();
        }
        send_status_message();
    }
}

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR Args, int WinMode) {
    LPSTR command_line;
    char* argv[100];
    int argc;
    
    command_line = GetCommandLineA();
    argc = parse_command_line( command_line, argv );
    return main(argc, argv);
}
#endif
