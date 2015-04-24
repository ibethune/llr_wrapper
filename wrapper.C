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

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#include "procinfo.h"
#include "boinc_api.h"
#include "diagnostics.h"
#include "filesys.h"
#include "error_numbers.h"
#include "util.h"

#define POLL_PERIOD 1.0

#define STR2(x) #x
#define STR(x) STR2(x)

#ifndef ARCH_TRIPLET
#error "ARCH_TRIPLET must be defined e.g. x86_64-apple-darwin"
#endif

#ifndef BITNESS
#error "BITNESS must be defined e.g. 64 or 32"
#endif

// The name of the executable that does the actual work:
const std::string capp_name = "primegrid_llr_" STR(ARCH_TRIPLET);
const std::string ini_file_name = "llr.ini.orig";
const std::string in_file_name = "llr.in";
const std::string out_file_name = "llr.out";
const std::string llr_args = "-d";

int fdOutputRead;
bool bGotFFT = false;

template <typename Out> Out StringTo(const std::string& input)
{
	std::stringstream	convert;
	Out 				output = Out();

	convert << input;
	convert >> output;
	return output;
}

struct TASK
{
	double progress;
	double old_progress;
	double old_time;
	double old_checkpoint_time;
    int pid;

    TASK() : progress(0.0),
				old_progress(0.0), old_time(0.0), old_checkpoint_time(0.0),
				pid(0) {}

    bool poll(int& status);
    int run(const std::string& app);
    void kill();
    void stop();
    void resume();
    double cpu_time();
    double wall_cpu_time;
};

bool app_suspended = false;

int TASK::run(const std::string& app)
{
    int retval;

    int fd_out[2];
    if (pipe(fd_out) < 0) {
      fprintf(stderr, "Failed to create pipe\n");
      return 250; // 250: Failed to create pipe
    }
    wall_cpu_time = 0;

    pid = fork();
    if (pid == -1) {
        boinc_finish(ERR_FORK);
    }
    if (pid == 0) {
		// we're in the child process here

        close(fd_out[0]);
        dup2(fd_out[1],STDOUT_FILENO);
        std::cerr << "wrapper: running " << app << " " << llr_args << std::endl;
        setpriority(PRIO_PROCESS, 0, PROCESS_IDLE_PRIORITY);
        retval = execl(app.c_str(), app.c_str(), llr_args.c_str(), NULL);
        std::cerr << "execv failed: " << strerror(errno) << std::endl;
        exit(ERR_EXEC);
    }else{
      // In the parent process
      close(fd_out[1]);
      /* Prevent parent read() blocking on child output pipe. */
      fcntl(fd_out[0],F_SETFL,fcntl(fd_out[0],F_GETFL)|O_NONBLOCK);
      fdOutputRead = fd_out[0];
    }
 
    app_suspended = false;
    return 0;
}

bool TASK::poll(int& status)
{
    int wpid;
    struct rusage ru;

    if (!app_suspended) wall_cpu_time += POLL_PERIOD;

    wpid = wait4(pid, &status, WNOHANG, &ru);
    if (wpid)
        return true;
    return false;
}

void TASK::kill()
{
    ::kill(pid, SIGKILL);
}

void TASK::stop()
{
    ::kill(pid, SIGSTOP);
}

void TASK::resume()
{
    ::kill(pid, SIGCONT);
}

void poll_boinc_messages(TASK& task)
{
    BOINC_STATUS status;
    boinc_get_status(&status);
    if (status.no_heartbeat)
    {
        task.kill();
        exit(0);
    }
    if (status.quit_request)
    {
        task.kill();
        exit(0);
    }
    if (status.abort_request)
    {
        task.kill();
        exit(0);
    }
    if (status.suspended)
    {
        if (!app_suspended)
        {
            task.stop();
            app_suspended = true;
        }
    }
    else
    {
        if (app_suspended)
        {
            task.resume();
            app_suspended = false;
        }
    }
}

double TASK::cpu_time()
{
    return wall_cpu_time;
}


double read_status()
{
  char buf[256];
  ssize_t len;
  if ((len = read(fdOutputRead,buf,sizeof(buf)-1)) > 0)
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
            fprintf(stderr,"FFT length: %d%s\n",x,(ch=='K')?"K":"");
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

void send_status_message(TASK& task, double checkpoint_period)
{
	double new_checkpoint_time = task.old_checkpoint_time;
	double cputime = task.cpu_time();

	task.old_progress = task.progress;
	task.progress = read_status();
	new_checkpoint_time = cputime + task.old_time;
	if (task.progress > task.old_progress)
		task.old_checkpoint_time = new_checkpoint_time;

        if (task.progress < 0)
          task.progress = task.old_progress;

    boinc_report_app_status(
        cputime + task.old_time,
        task.old_checkpoint_time,
        task.progress
    );
}

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


int main(int argc, char** argv)
{
    BOINC_OPTIONS options;
    int retval;

    boinc_init_diagnostics(
        BOINC_DIAG_DUMPCALLSTACKENABLED |
        BOINC_DIAG_HEAPCHECKENABLED |
//        BOINC_DIAG_MEMORYLEAKCHECKENABLED |
        BOINC_DIAG_TRACETOSTDERR |
        BOINC_DIAG_REDIRECTSTDERR
    );

    memset(&options, 0, sizeof(options));
    options.main_program = true;
    options.check_heartbeat = true;
    options.handle_process_control = true;

    std::cerr << "BOINC llr wrapper" << std::endl;
    std::cerr << "Using Jean Penne's llr (" << BITNESS << " bit)\n" << std::endl;

    boinc_init_options(&options);

	APP_INIT_DATA uc_aid;
	boinc_get_init_data(uc_aid);
	if (uc_aid.checkpoint_period < 1.0)
		uc_aid.checkpoint_period = 60.0;

	// Copy files:
	std::string resolved_file;
	boinc_resolve_filename_s(ini_file_name.c_str(), resolved_file);
	boinc_copy(resolved_file.c_str(), "llr.ini");

	boinc_resolve_filename_s(in_file_name.c_str(), resolved_file);
	boinc_copy(resolved_file.c_str(), "llrin.txt");

        std::string orig_capp_name = capp_name + std::string(".orig");
	boinc_resolve_filename_s(orig_capp_name.c_str(), resolved_file);
	boinc_copy(resolved_file.c_str(), capp_name.c_str());

	// Start application:
	TASK t;
    boinc_wu_cpu_time(t.old_time);
	t.old_checkpoint_time = t.old_time;

	retval = t.run(capp_name);
	if (retval)
	{
		std::cerr <<  "can't run app: " << capp_name << std::endl;
		boinc_finish(retval);
	}
	for(;;)
	{
		int status;
		if (t.poll(status))
		{
			int child_ret_val = WEXITSTATUS(status);
			if (child_ret_val)
			{
				std::cerr << "app error: " <<  status << std::endl;
				boinc_finish(status);
			}
			break;
		}
		poll_boinc_messages(t);
		send_status_message(t, uc_aid.checkpoint_period);
		boinc_sleep(POLL_PERIOD);
	}
	// Parse output file to remove checkpoint messages
	std::string stri;
	char cLine[256];
	std::ifstream FR; // Read
	std::ofstream FW; // Write
	int iSignPos = -1;
	int iCount = 0;
	FR.open("lresults.txt");
	FW.open("lresults_parsed.txt");
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

	//Convert line-endings:
	if (!unix2dos("lresults_parsed.txt", "lresults_parsed.txt.dos"))
	{
		std::cerr << "failed to convert line endings!" << std::endl;
		boinc_finish(-1);
		return 1;
	}

	// Save result file:
	boinc_resolve_filename_s(out_file_name.c_str(), resolved_file);
	boinc_copy("lresults_parsed.txt.dos", resolved_file.c_str());


    boinc_finish(0);
}
