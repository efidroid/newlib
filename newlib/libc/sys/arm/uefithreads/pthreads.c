#include <Base.h>
#include <PiDxe.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/UefiThread.h>

#include <_ansi.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <malloc.h>
#include <string.h>

#include "list.h"

typedef void (*destr_function)(void *);

typedef struct {
  list_node_t node;

  destr_function destructor;
  void *data;
} nothreads_key_entry_t;

typedef struct {
  THREAD t;
  pthread_mutex_t mutex;
  void * (*start_routine)(void *);
  void *arg;

  pthread_attr_t attrs;
  int cancelstate;
  int canceltype;
  int canceled;
} pthread_internal_t;

typedef struct {
  list_node_t node;

  THREAD_EVENT wait_event;
} cond_waiter_context_t;

typedef struct {
  pthread_mutex_t mutex;
  list_node_t waiters;
} cond_context_t;

extern UEFI_THREAD_PROTOCOL *__libc_mThreads;
extern THREAD __libc_mMainThread;

static UINTN tls_cleanup;
static UINTN tls_internaldata;
static void cleanup_destructor(void *pdata);
static void internaldata_destructor(void *pdata);

static int nothreads_pthread_cancelstate = PTHREAD_CANCEL_ENABLE;
static list_node_t nothreads_keys = LIST_INITIAL_VALUE(nothreads_keys);
static void *nothreads_tls_cleanup = NULL;

void __libc_init_pthreads(void) {
  EFI_STATUS status;
  if (__libc_mThreads) {
    status = __libc_mThreads->TlsCreate(&tls_cleanup, cleanup_destructor);
    assert(status==EFI_SUCCESS);

    status = __libc_mThreads->TlsCreate(&tls_internaldata, internaldata_destructor);
    assert(status==EFI_SUCCESS);

    pthread_internal_t *ithread = malloc(sizeof(pthread_internal_t));
    assert(ithread);
    pthread_attr_init(&ithread->attrs);
    ithread->cancelstate = PTHREAD_CANCEL_ENABLE;
    ithread->canceltype = PTHREAD_CANCEL_DEFERRED;
    ithread->start_routine = NULL;
    ithread->arg = NULL;
    ithread->canceled = 0;
    pthread_mutex_init(&ithread->mutex, NULL);
    ithread->t = __libc_mMainThread;
    __libc_mThreads->TlsSet(tls_internaldata, ithread);
  }
}

int pthread_setcancelstate(int state, int * poldstate) {
  if (!__libc_mThreads) {
    if (poldstate) {
      *poldstate = nothreads_pthread_cancelstate;
    }
    nothreads_pthread_cancelstate = state;
    return 0;
  }

  pthread_internal_t *ithread = __libc_mThreads->TlsGet(tls_internaldata);
  assert(ithread);
  pthread_mutex_lock(&ithread->mutex);
  int oldstate = ithread->cancelstate;
  ithread->cancelstate = state;

  if (poldstate)
    *poldstate = oldstate;

  if (ithread->canceled && state==PTHREAD_CANCEL_ENABLE && ithread->canceltype==PTHREAD_CANCEL_ASYNCHRONOUS)
  {
    pthread_mutex_unlock(&ithread->mutex);
    __libc_mThreads->ThreadExit((INTN)PTHREAD_CANCELED);
    return -1;
  }

  pthread_mutex_unlock(&ithread->mutex);

  return 0;
}

int pthread_attr_init(pthread_attr_t *attr)
{
  assert(attr);

  attr->detachstate = PTHREAD_CREATE_JOINABLE;
  attr->is_initialized = 1;

  return 0;
}

int pthread_attr_destroy(pthread_attr_t *attr)
{
  assert(attr);
  assert(attr->is_initialized);

  attr->is_initialized = 0;

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
  if (!__libc_mThreads) {
    assert(0);
    errno = ENOSYS;
    return -1;
  }

  pthread_internal_t *ithread = (pthread_internal_t*)thread;

  pthread_mutex_lock(&ithread->mutex);
  ithread->canceled = 1;
  pthread_mutex_unlock(&ithread->mutex);

  return 0;
}

void pthread_testcancel(void) {
  if (!__libc_mThreads) {
    assert(0);
    errno = ENOSYS;
    return;
  }

  pthread_internal_t *ithread = __libc_mThreads->TlsGet(tls_internaldata);
  assert(ithread);

  pthread_mutex_lock(&ithread->mutex);
  if (ithread->canceled && ithread->cancelstate==PTHREAD_CANCEL_ENABLE) {
    pthread_mutex_unlock(&ithread->mutex);
    __libc_mThreads->ThreadExit((INTN)PTHREAD_CANCELED);
    return;
  }
  pthread_mutex_unlock(&ithread->mutex);
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
  int rc;

  assert(cond);

  if (!__libc_mThreads) {
    return 0;
  }

  cond_context_t *ctx = malloc(sizeof(cond_context_t));
  if (!ctx) {
    return -1;
  }
  list_initialize(&ctx->waiters);

  rc = pthread_mutex_init(&ctx->mutex, NULL);
  if (rc) {
    free(ctx);
    return rc;
  }

  *cond = (pthread_cond_t)ctx;

  return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond)
{
  assert(cond);

  if (!__libc_mThreads) {
    return 0;
  }

  cond_context_t *ctx = (cond_context_t*)*cond;
  assert(list_is_empty(&ctx->waiters));
  pthread_mutex_destroy(&ctx->mutex);

  return 0;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
  return pthread_cond_timedwait(cond, mutex, NULL);
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                           const struct timespec * abstime)
{
  EFI_STATUS status;
  int rc;

  assert(mutex);

  if (!__libc_mThreads) {
    assert(0);
    errno = ENOSYS;
    return -1;
  }

  cond_context_t *ctx = (cond_context_t*)*cond;

  cond_waiter_context_t waiter_ctx;
  status = __libc_mThreads->EventCreate(&waiter_ctx.wait_event, 0, THREAD_EVENT_FLAG_AUTOUNSIGNAL);
  if (EFI_ERROR(status)) {
    return -1;
  }

  pthread_mutex_lock(&ctx->mutex);
  list_add_tail(&ctx->waiters, &waiter_ctx.node);
  pthread_mutex_unlock(&ctx->mutex);

  pthread_mutex_unlock(mutex);

  if (abstime) {
    struct timespec reltime;
    clock_gettime(CLOCK_REALTIME, &reltime);
    reltime.tv_sec = abstime->tv_sec - reltime.tv_sec;
    reltime.tv_nsec = abstime->tv_nsec - reltime.tv_nsec;

    THREAD_TIME_MS ms = reltime.tv_sec * 1000;
    ms += reltime.tv_nsec / 1000000;

    if (ms > 0)
      status = __libc_mThreads->EventWaitTimeout(waiter_ctx.wait_event, ms);
    else
      status = EFI_TIMEOUT;
  }
  else {
    status = __libc_mThreads->EventWait(waiter_ctx.wait_event);
  }

  if (status == EFI_TIMEOUT)
    rc = ETIMEDOUT;
  else if (EFI_ERROR(status)) {
    rc = -1;
  }

  pthread_mutex_lock(mutex);

  __libc_mThreads->EventDestroy(waiter_ctx.wait_event);

  return rc;
}

int pthread_cond_signal(pthread_cond_t *cond)
{
  EFI_STATUS status;

  assert(cond);

  if (!__libc_mThreads) {
    assert(0);
    errno = ENOSYS;
    return -1;
  }

  cond_context_t *ctx = (cond_context_t*)*cond;

  pthread_mutex_lock(&ctx->mutex);

  cond_waiter_context_t * waiter_ctx = list_remove_head_type(&ctx->waiters, cond_waiter_context_t, node);
  if (waiter_ctx) {
    status = __libc_mThreads->EventSignal(waiter_ctx->wait_event, 0);
    assert(status==EFI_SUCCESS);
  }

  pthread_mutex_unlock(&ctx->mutex);

  return 0;
}

int pthread_cond_broadcast(pthread_cond_t *cond)
{
  EFI_STATUS status;

  assert(cond);

  if (!__libc_mThreads) {
    assert(0);
    errno = ENOSYS;
    return -1;
  }

  cond_context_t *ctx = (cond_context_t*)*cond;

  pthread_mutex_lock(&ctx->mutex);

  while(!list_is_empty(&ctx->waiters)) {
    cond_waiter_context_t * waiter_ctx = list_remove_head_type(&ctx->waiters, cond_waiter_context_t, node);
    if (waiter_ctx) {
      status = __libc_mThreads->EventSignal(waiter_ctx->wait_event, 0);
      assert(status==EFI_SUCCESS);
    }
  }

  pthread_mutex_unlock(&ctx->mutex);

  return 0;
}

static void internaldata_destructor(void *pdata) {
  pthread_internal_t *ithread = pdata;

  if (ithread->attrs.detachstate==PTHREAD_CREATE_DETACHED)
    free(ithread);
}

static INTN pthread_start_routine(void *pdata) {
  void *retval;
  pthread_internal_t *ithread = pdata;

  __libc_mThreads->TlsSet(tls_internaldata, ithread);

  retval = ithread->start_routine(ithread->arg);
  __libc_mThreads->TlsSet(tls_cleanup, NULL);

  return (INTN)retval;
};

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
			 void * (*start_routine)(void *), void *arg)
{
  if (!__libc_mThreads) {
    errno = ENOSYS;
    return -1;
  }

  THREAD t;
  EFI_STATUS status;

  pthread_internal_t *ithread = malloc(sizeof(pthread_internal_t));
  if(!ithread)
    return -1;
  if (attr)
    ithread->attrs = *attr;
  else
    pthread_attr_init(&ithread->attrs);
  ithread->cancelstate = PTHREAD_CANCEL_ENABLE;
  ithread->canceltype = PTHREAD_CANCEL_DEFERRED;
  ithread->start_routine = start_routine;
  ithread->arg = arg;
  ithread->canceled = 0;
  pthread_mutex_init(&ithread->mutex, NULL);

  status = __libc_mThreads->ThreadCreate(&t, "pthread", pthread_start_routine, ithread, DEFAULT_PRIORITY, 0x10000);
  if (EFI_ERROR(status)) {
    return -1;
  }
  ithread->t = t;

  if (attr && attr->detachstate==PTHREAD_CREATE_DETACHED) {
    status = __libc_mThreads->ThreadDetach(t);
    if (EFI_ERROR(status)) {
      return -1;
    }
  }

  status = __libc_mThreads->ThreadResume(t);
  if (EFI_ERROR(status)) {
    return -1;
  }

  *thread = (pthread_t)t;
  return 0;
}

int pthread_join(pthread_t thread, void **retval) {
  EFI_STATUS status;

  if (!__libc_mThreads) {
    errno = ENOSYS;
    return -1;
  }

  pthread_internal_t *ithread = (pthread_internal_t*)thread;

  status = __libc_mThreads->ThreadJoin((THREAD)thread, (INTN*)retval, INFINITE_TIME);
  if (EFI_ERROR(status))
    return EINVAL;

  free(ithread);

  return 0;
}

void * pthread_getspecific(pthread_key_t key)
{
  if (__libc_mThreads) {
    return __libc_mThreads->TlsGet((UINTN)key);
  }
  else {
    nothreads_key_entry_t *entry = (nothreads_key_entry_t*)key;
    return entry->data;
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
    nothreads_key_entry_t *entry = (nothreads_key_entry_t*)key;
    entry->data = (void*)pointer;
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
    nothreads_key_entry_t *entry = malloc(sizeof(nothreads_key_entry_t));
    if(!entry)
      return -1;

    entry->destructor = destr;
    entry->data = NULL;
    list_add_tail(&nothreads_keys, &entry->node);

    *key = (pthread_key_t) entry;
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
  else {
    nothreads_key_entry_t *entry = (nothreads_key_entry_t*)key;
    list_delete(&entry->node);
    free(entry);
  }

  return 0;
}

int pthread_mutexattr_init(pthread_mutexattr_t *attr) {
  memset(attr, 0, sizeof(*attr));
  attr->is_initialized = 1;
  attr->type = PTHREAD_MUTEX_DEFAULT;
  return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *attr) {
  assert(attr->is_initialized==1);
  attr->is_initialized = 0;
  return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type) {
  assert(attr->is_initialized==1);

  attr->type = type;
}

int pthread_mutex_init(pthread_mutex_t * mutex,
                       const pthread_mutexattr_t * mutex_attr)
{
  EFI_STATUS status;

  // TODO: implement mutex_attr
  assert(mutex_attr==NULL);

  if (!__libc_mThreads) {
    return 0;
  }

  status = __libc_mThreads->MutexCreate((MUTEX*)mutex);
  if (EFI_ERROR(status)) {
    return -1;
  }

  return 0;
}

int pthread_mutex_destroy(pthread_mutex_t * mutex)
{
  if (!__libc_mThreads) {
    return 0;
  }

  __libc_mThreads->MutexDestroy((MUTEX)*mutex);
  return 0;
}

int pthread_mutex_lock(pthread_mutex_t * mutex)
{
  EFI_STATUS status;

  if (!__libc_mThreads) {
    return 0;
  }

  status = __libc_mThreads->MutexAcquire((MUTEX)*mutex);
  if (EFI_ERROR(status)) {
    return -1;
  }

  return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
  if (!__libc_mThreads) {
    return 0;
  }

  if (__libc_mThreads->MutexHeld((MUTEX)*mutex))
    return EBUSY;

  return pthread_mutex_lock(mutex);
}

int pthread_mutex_unlock(pthread_mutex_t * mutex)
{
  EFI_STATUS status;

  if (!__libc_mThreads) {
    return 0;
  }

  status = __libc_mThreads->MutexRelease((MUTEX)*mutex);
  if (EFI_ERROR(status)) {
    return -1;
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
    t = (pthread_t) 1;
  }

  return t;
}

static void cleanup_destructor(void *pdata) {
  struct _pthread_cleanup_context *c;

  if (__libc_mThreads)
    c = __libc_mThreads->TlsGet(tls_cleanup);
  else
    c = nothreads_tls_cleanup;

  while (c != NULL) {
    c->_routine(c->_arg);
    c = c->_previous;
  }
}

void _pthread_cleanup_push(struct _pthread_cleanup_context *buffer,
                           void (*routine)(void *), void *arg)
{
  buffer->_routine = routine;
  buffer->_arg = arg;
  buffer->_previous = __libc_mThreads->TlsGet(tls_cleanup);

  if (__libc_mThreads)
    __libc_mThreads->TlsSet(tls_cleanup, buffer);
  else
    nothreads_tls_cleanup = buffer;
}

void _pthread_cleanup_pop(struct _pthread_cleanup_context *buffer, int execute)
{
  if (execute) buffer->_routine(buffer->_arg);

  if (__libc_mThreads)
    __libc_mThreads->TlsSet(tls_cleanup, buffer->_previous);
  else
    nothreads_tls_cleanup = buffer->_previous;
}

int	pthread_setname_np(pthread_t t, const char *name) {
  if (!__libc_mThreads) {
    return 0;
  }

  __libc_mThreads->ThreadSetName((THREAD)t, name);
  return 0;
}
