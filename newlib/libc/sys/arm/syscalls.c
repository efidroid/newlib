/* Support files for GNU libc.  Files in the system namespace go here.
   Files in the C namespace (ie those that do not start with an
   underscore) go in .c.  */

#include <Base.h>
#include <PiDxe.h>
#include <Library/UefiBootServicesTableLib.h>

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

extern jmp_buf _exit_jmp_buf;
extern int _exit_return_value;

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
  uint8_t c16[4] = {0};

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
      if (*ptr=='\n')
          ustr_len++;

        ustr_len++;
    }
    CHAR16 *ustr = malloc(ustr_len + 1);
    if (!ustr) return -1;

    size_t pos = 0;
    for (i = 0; i < len; i++) {
      if (*ptr=='\n') {
          ustr[pos++] = '\r';
      }

      ustr[pos++] = (CHAR16)(*ptr++);
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
