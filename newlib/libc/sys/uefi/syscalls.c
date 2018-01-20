/* Support files for GNU libc.  Files in the system namespace go here.
   Files in the C namespace (ie those that do not start with an
   underscore) go in .c.  */

#include <Base.h>
#include <PiDxe.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/UefiThread.h>
#include <Protocol/Timestamp.h>

#include <_ansi.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include <errno.h>
#include <reent.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <setjmp.h>
#include <stdlib.h>
#include <dirent.h>
#include <assert.h>
#include <pthread.h>

void __libc_efi_puts(const char *s);

extern jmp_buf _exit_jmp_buf;
extern int _exit_return_value;
static EFI_GUID mUefiThreadProtocolGuid = UEFI_THREAD_PROTOCOL_GUID;
static EFI_GUID mEfiTimestampProtocolGuid = EFI_TIMESTAMP_PROTOCOL_GUID;
static EFI_TIMESTAMP_PROTOCOL *mTimestamp = NULL;
static EFI_TIMESTAMP_PROPERTIES mTimestampProperties;
UEFI_THREAD_PROTOCOL *__libc_mThreads = NULL;
THREAD __libc_mMainThread;

__weak_symbol void __libc_init_pthreads(void) {
}

void __libc_init_syscalls(void) {
  EFI_STATUS status;

  gST->BootServices->LocateProtocol (&mUefiThreadProtocolGuid, NULL, (void **)&__libc_mThreads);
  if (__libc_mThreads) {
    __libc_mMainThread = __libc_mThreads->ThreadSelf();
  }

  status = gST->BootServices->LocateProtocol (&mEfiTimestampProtocolGuid, NULL, (void **)&mTimestamp);
  if (!EFI_ERROR(status)) {
    status = mTimestamp->GetProperties(&mTimestampProperties);
    if (EFI_ERROR(status)) {
      mTimestamp = NULL;
    }
  }

  __libc_init_pthreads();
}

/* Forward prototypes.  */
int     _system     _PARAMS ((const char *));
int     _rename     _PARAMS ((const char *, const char *));
int     _isatty		_PARAMS ((int));
clock_t _times		_PARAMS ((struct tms *));
int     _gettimeofday	_PARAMS ((struct timeval *, void *));
void    _raise 		_PARAMS ((void));
int     _unlink		_PARAMS ((const char *));
int     _link 		_PARAMS ((void));
int     _stat 		_PARAMS ((const char *, struct stat *));
int     _fstat 		_PARAMS ((int, struct stat *));
int     _getpid		_PARAMS ((int));
int     _kill		_PARAMS ((int, int));
void    _exit		_PARAMS ((int));
int     _close		_PARAMS ((int));
int     _open		_PARAMS ((const char *, int, ...));
int     _write 		_PARAMS ((int, char *, int));
int     _lseek		_PARAMS ((int, int, int));
int     _read		_PARAMS ((int, char *, int));

/* Register name faking - works in collusion with the linker.  */
register char * stack_ptr asm ("sp");


/* following is copied from libc/stdio/local.h to check std streams */
extern void   _EXFUN(__sinit,(struct _reent *));
#define CHECK_INIT(ptr) \
  do						\
    {						\
      if ((ptr) && !(ptr)->__sdidinit)		\
	__sinit (ptr);				\
    }						\
  while (0)

static void micro_second_delay(uint64_t us) {
  volatile uint64_t count;
  uint64_t init_count;
  uint64_t timeout;
  uint64_t ticks;

  // calculate number of ticks we have to wait
  ticks = (us * mTimestampProperties.Frequency) / 1000000LLU;

  // get current counter value
  count = mTimestamp->GetTimestamp();
  init_count = count;

  // Calculate timeout = cnt + ticks (mod 2^56)
  // to account for timer counter wrapping
  timeout = (count + ticks) & mTimestampProperties.EndValue;

  // Wait out till the counter wrapping occurs
  // in cases where there is a wrapping.
  while (timeout < count && init_count <= count)
    count = mTimestamp->GetTimestamp();

  // Wait till the number of ticks is reached
  while (timeout > count)
    count = mTimestamp->GetTimestamp();
}

int __attribute__((weak))
_read (int file,
       char * ptr,
       int len)
{
  errno = ENOSYS;
  return -1;
}

int
_lseek (int file,
	int ptr,
	int dir)
{
  errno = ENOSYS;
  return -1;
}

int __attribute__((weak))
_write (int    file,
	char * ptr,
	int    len)
{
  int i;

  if (file == 1 || file == 2) {
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *con;
    if (file==2)
        con = gST->StdErr?:gST->ConOut;
    else if (file==1)
        con = gST->ConOut;

    if (con==NULL)
        return -1;

    size_t ustr_len = 0;
    for (i = 0; i < len; i++) {
      if (ptr[i]=='\n')
          ustr_len++;

      ustr_len++;
    }
    ustr_len++;

    CHAR16 *ustr = malloc(sizeof(CHAR16) * (ustr_len));
    if (!ustr) return -1;

    size_t pos = 0;
    for (i = 0; i < len; i++) {
      if (ptr[i]=='\n') {
          ustr[pos++] = '\r';
      }

      ustr[pos++] = (CHAR16)(ptr[i]);
    }
    ustr[pos++] = 0;

    con->OutputString(con, ustr);
    free(ustr);
  }
  else {
    errno = EBADF;
    return -1;
  }

  return len;
}

int
_open (const char * path,
       int          flags,
       ...)
{
  errno = ENOSYS;
  return -1;
}

int
_close (int file)
{
  errno = ENOSYS;
  return -1;
}

int access(const char *fn, int flags)
{
  struct stat s;
  if (stat(fn, &s))
    return -1;
  if (s.st_mode & S_IFDIR)
    return 0;
  if (flags & W_OK)
  {
    if (s.st_mode & S_IWRITE)
      return 0;
    return -1;
  }
  return 0;
}

int
_kill (int pid, int sig)
{
  (void)pid; (void)sig;

  if (pid==getpid()) {
    exit(1);
    return 0;
  }

  errno = ESRCH;
  return -1;
}

void
_exit (int status)
{
  _exit_return_value = status;

  if (__libc_mThreads && __libc_mThreads->ThreadSelf() != __libc_mMainThread) {
    __libc_efi_puts("called exit() from a thread. waiting forever\n");
    for(;;);
  }

  longjmp(_exit_jmp_buf, 1);
}

int
_getpid (int n)
{
  return 1;
  n = n;
}

int
_fstat (int file, struct stat * st)
{
  errno = ENOSYS;
  return -1;
}

int _stat (const char *fname, struct stat *st)
{
  errno = ENOSYS;
  return -1;
}

int
_link (void)
{
  return -1;
}

int
_unlink (const char *path)
{
  return -1;
}

void
_raise (void)
{
  assert(0);
  return;
}

int
_gettimeofday (struct timeval * tp, void * tzvp)
{
  errno = ENOSYS;
  return -1;
}

/* Return a clock that ticks at 100Hz.  */
clock_t 
_times (struct tms * tp)
{
  errno = ENOSYS;
  return -1;
};


int
_isatty (int fd)
{
  return (fd <= 2) ? 1 : 0;  /* one of stdin, stdout, stderr */
}

int
_system (const char *s)
{
  if (s == NULL)
    return 0;
  errno = ENOSYS;
  return -1;
}

int
_rename (const char * oldpath, const char * newpath)
{
  errno = ENOSYS;
  return -1;
}

int	chmod( const char *__path, mode_t __mode ) {
  errno = ENOSYS;
  return -1;
}

int fchmod(int __fildes, mode_t __mode ) {
  errno = ENOSYS;
  return -1;
}

int flock(int fd, int b) {
  errno = ENOSYS;
  return -1;
}

int fsync(int __fd) {
  errno = ENOSYS;
  return -1;
}

int ftruncate(int __fd, off_t __length) {
  errno = ENOSYS;
  return -1;
}

int truncate(const char *path, off_t __length) {
  errno = ENOSYS;
  return -1;
}

int fchown(int fd, uid_t owner, gid_t group) {
  errno = ENOSYS;
  return -1;
}

int utimes(const char *path, const struct timeval times[2]) {
  errno = ENOSYS;
  return -1;
}

ssize_t readlink(const char *__restrict __path,
                          char *__restrict __buf, size_t __buflen)
{
  errno = ENOSYS;
  return -1;
}

int symlink(const char *__name1, const char *__name2) {
  errno = ENOSYS;
  return -1;
}

int	mkdir( const char *_path, mode_t __mode ) {
  errno = ENOSYS;
  return -1;
}

int rmdir(const char *__path) {
  errno = ENOSYS;
  return -1;
}

char *
getcwd (char *pt, size_t size)
{
  if (size<2) {
    return NULL;
  }

  snprintf(pt, size, "/");
  return pt;
}

int chdir(const char *__path )
{
  errno = ENOSYS;
  return -1;
}

uid_t geteuid(void) {
  return 0;
}

uid_t getuid(void) {
  return 0;
}

int clock_gettime(clockid_t clock_id, struct timespec *tp) {
  uint64_t ns;
  assert(clock_id == CLOCK_REALTIME);

  if (__libc_mThreads) {
    ns = __libc_mThreads->CurrentTimeNs();
  }
  else {
    errno = ENOSYS;
    return -1;
  }

  tp->tv_sec = ns / 1000000000;
  tp->tv_nsec = ns - tp->tv_sec*1000000000;

  return 0;
}

int usleep(useconds_t usec) {
  if (mTimestamp) {
    micro_second_delay(usec);
    return 0;
  }

  errno = ENOSYS;
  return -1;
}

unsigned int sleep(unsigned int seconds) {
    return usleep(seconds * 1000000);
}

int nanosleep (const struct timespec  *rqtp, struct timespec *rmtp) {
  if (mTimestamp) {
    // Round up to 1us Tick Number
    uint64_t us = 0;
    us += rqtp->tv_sec * 1000000ULL;
    us += rqtp->tv_nsec / 1000;
    us += ((rqtp->tv_nsec % 1000) == 0) ? 0 : 1;

    micro_second_delay(us);
    return 0;
  }

  errno = ENOSYS;
  return -1;
}

int sched_yield( void ) {
  if (__libc_mThreads) {
    __libc_mThreads->ThreadYield();
  }

  return 0;
}

// newlib uses this for locking so define this as a weak symbol
// in case we're not linking against libpthread
__weak_symbol int pthread_setcancelstate(int state, int * oldstate) {
  return 0;
}

DIR *opendir (const char *path) {
  errno = ENOSYS;
  return NULL;
}

struct dirent *readdir (DIR *d) {
  return NULL;
}

int closedir (DIR *d) {
  errno = ENOSYS;
  return -1;
}
