#include <Base.h>
#include <PiDxe.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/UefiThread.h>

#include <_ansi.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

typedef void (*destr_function)(void *);

typedef struct {
    destr_function destructor;
    void *data;
} key_entry_t;

extern UEFI_THREAD_PROTOCOL *__libc_mThreads;

static int nothreads_pthread_cancelstate = PTHREAD_CANCEL_ENABLE;
static int nothreads_current_key = 1;
static key_entry_t nothreads_key_data[1024];

int pthread_setcancelstate(int state, int * oldstate) {
    *oldstate = nothreads_pthread_cancelstate;
    nothreads_pthread_cancelstate = state;
    return 0;
}

int pthread_attr_init(pthread_attr_t *attr)
{
  return 0;
}


int pthread_attr_destroy(pthread_attr_t *attr)
{
  return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate)
{
  if (detachstate < PTHREAD_CREATE_JOINABLE ||
      detachstate > PTHREAD_CREATE_DETACHED)
    return EINVAL;
  attr->detachstate = detachstate;
  return 0;
}

int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate)
{
  *detachstate = attr->detachstate;
  return 0;
}

int pthread_cancel(pthread_t thread) {
  assert(0);
  return -1;
}

void pthread_testcancel(void) {
  assert(0);
}

int pthread_condattr_init(pthread_condattr_t *attr)
{
  assert(attr);

  attr->is_initialized = 1;

  return 0;
}

int pthread_condattr_destroy(pthread_condattr_t *attr)
{
  assert(attr);
  assert(attr->is_initialized);

  attr->is_initialized = 0;

  return 0;
}

int pthread_cond_init(pthread_cond_t *cond,
                      const pthread_condattr_t *cond_attr)
{
  EFI_STATUS status;

  assert(cond);

  if (__libc_mThreads) {
    status = __libc_mThreads->EventCreate((THREAD_EVENT*)cond, 0, THREAD_EVENT_FLAG_AUTOUNSIGNAL);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }

  return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond)
{
  assert(cond);

  if (__libc_mThreads) {
    __libc_mThreads->EventDestroy((THREAD_EVENT)*cond);
  }
  return 0;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
  EFI_STATUS status;

  assert(mutex);

  if (__libc_mThreads) {
    status = __libc_mThreads->EventWait((THREAD_EVENT)*cond);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }
  else {
    assert(0);
  }

  return 0;
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                           const struct timespec * abstime)
{
  assert(0);
  return 0;
}

int pthread_cond_signal(pthread_cond_t *cond)
{
  EFI_STATUS status;

  assert(cond);

  if (__libc_mThreads) {
    status = __libc_mThreads->EventSignal((THREAD_EVENT)*cond, 1);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }
  else {
    assert(0);
  }

  return 0;
}

int pthread_cond_broadcast(pthread_cond_t *cond)
{
  assert(0);
  return 0;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
			 void * (*start_routine)(void *), void *arg)
{
  assert(0);
  return 0;
}

void * pthread_getspecific(pthread_key_t key)
{
  if (__libc_mThreads) {
    return __libc_mThreads->TlsGet((UINTN)key);
  }
  else {
    return nothreads_key_data[key].data;
  }
}

int pthread_setspecific(pthread_key_t key, const void * pointer)
{
  EFI_STATUS status;

  if (__libc_mThreads) {
    status = __libc_mThreads->TlsSet((UINTN)key, (void*)pointer);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }
  else {
    nothreads_key_data[key].data = (void*)pointer;
  }

  return 0;
}

int pthread_key_create(pthread_key_t * key, destr_function destr)
{
  EFI_STATUS status;

  if (__libc_mThreads) {
    status = __libc_mThreads->TlsCreate((UINTN*)key, destr);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }
  else {
    int idx = nothreads_current_key++;
    nothreads_key_data[idx].destructor = destr;
    nothreads_key_data[idx].data = NULL;
    *key = idx;
  }

  return 0;
}

int pthread_key_delete(pthread_key_t key)
{
  EFI_STATUS status;

  if (__libc_mThreads) {
    status = __libc_mThreads->TlsDelete((UINTN)key);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }

  return 0;
}

int pthread_mutex_init(pthread_mutex_t * mutex,
                       const pthread_mutexattr_t * mutex_attr)
{
  EFI_STATUS status;

  assert(mutex_attr==NULL);

  if (__libc_mThreads) {
    status = __libc_mThreads->MutexCreate((MUTEX*)mutex);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }

  return 0;
}

int pthread_mutex_destroy(pthread_mutex_t * mutex)
{
  if(__libc_mThreads) {
    __libc_mThreads->MutexDestroy((MUTEX)*mutex);
  }

  return 0;
}

int pthread_mutex_lock(pthread_mutex_t * mutex)
{
  EFI_STATUS status;

  if (__libc_mThreads) {
    status = __libc_mThreads->MutexAcquire((MUTEX)*mutex);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }

  return 0;
}

int pthread_mutex_unlock(pthread_mutex_t * mutex)
{
  EFI_STATUS status;

  if (__libc_mThreads) {
    status = __libc_mThreads->MutexRelease((MUTEX)*mutex);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }

  return 0;
}

int pthread_once(pthread_once_t * once_control, void (*init_routine)(void))
{
  THREAD t;
  assert(once_control);
  assert(once_control->is_initialized==1);

  if (once_control->init_executed) {
    return 0;
  }

  init_routine();
  once_control->init_executed = 1;

  return 0;
}

pthread_t pthread_self(void)
{
  pthread_t t;

  if (__libc_mThreads) {
    t =  (pthread_t)__libc_mThreads->ThreadSelf();
  }
  else {
    t = (pthread_t) 0x1000;
  }

  return t;
}

void _pthread_cleanup_push(struct _pthread_cleanup_context *_context,
                           void (*_routine)(void *), void *_arg)
{
  assert(0);
}

void _pthread_cleanup_pop(struct _pthread_cleanup_context *_context, int _execute)
{
  assert(0);
}
