#include "env-inl.h"
#include "base_object-inl.h"
#include "debug_utils-inl.h"
#include "memory_tracker-inl.h"
#include "node_mem-inl.h"
#include "util-inl.h"
#include "node.h"
#include "node_errors.h"
#include "uv.h"
#include "uvwasi.h"
#include "node_wasi.h"

namespace node {
namespace wasi {

template <typename... Args>
inline void Debug(WASI& wasi, Args&&... args) {
  Debug(wasi.env(), DebugCategory::WASI, std::forward<Args>(args)...);
}

template <typename... Args>
inline void Debug(WASI* wasi, Args&&... args) {
  Debug(wasi->env(), DebugCategory::WASI, std::forward<Args>(args)...);
}

#define ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(ptr, obj)                          \
  do {                                                                         \
    ASSIGN_OR_RETURN_UNWRAP(ptr, obj);                                         \
    if ((*(ptr))->memory_.IsEmpty()) {                                         \
      THROW_ERR_WASI_NOT_STARTED(Environment::GetCurrent(args));               \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define RETURN_IF_BAD_ARG_COUNT(args, expected)                               \
  do {                                                                        \
    if ((args).Length() != (expected)) {                                      \
      (args).GetReturnValue().Set(UVWASI_EINVAL);                             \
      return;                                                                 \
    }                                                                         \
  } while (0)

#define CHECK_TO_TYPE_OR_RETURN(args, input, type, result)                    \
  do {                                                                        \
    if (!(input)->Is##type()) {                                               \
      (args).GetReturnValue().Set(UVWASI_EINVAL);                             \
      return;                                                                 \
    }                                                                         \
    (result) = (input).As<type>()->Value();                                   \
  } while (0)

#define UNWRAP_BIGINT_OR_RETURN(args, input, type, result)                    \
  do {                                                                        \
    if (!(input)->IsBigInt()) {                                               \
      (args).GetReturnValue().Set(UVWASI_EINVAL);                             \
      return;                                                                 \
    }                                                                         \
    Local<BigInt> js_value = (input).As<BigInt>();                            \
    bool lossless;                                                            \
    (result) = js_value->type ## Value(&lossless);                            \
  } while (0)

#define GET_BACKING_STORE_OR_RETURN(wasi, args, mem_ptr, mem_size)             \
  do {                                                                         \
    Local<WasmMemoryObject> _memory =                                          \
        PersistentToLocal::Strong((wasi)->memory_);                            \
    std::shared_ptr<BackingStore> _backing_store =                             \
        _memory->Buffer()->GetBackingStore();                                  \
    *(mem_size) = _backing_store->ByteLength();                                \
    *(mem_ptr) = static_cast<char*>(_backing_store->Data());                   \
    CHECK(mem_ptr != nullptr);                                                 \
  } while (0)

#define CHECK_BOUNDS_OR_RETURN(args, mem_size, offset, buf_size)              \
  do {                                                                        \
    if (!uvwasi_serdes_check_bounds((offset), (mem_size), (buf_size))) {      \
      (args).GetReturnValue().Set(UVWASI_EOVERFLOW);                          \
      return;                                                                 \
    }                                                                         \
  } while (0)

#define CHECK_BOUNDS_OR_RETURN2(mem_size, offset, buf_size)                    \
  do {                                                                         \
    if (!uvwasi_serdes_check_bounds((offset), (mem_size), (buf_size))) {       \
      return UVWASI_EOVERFLOW;                                                 \
    }                                                                          \
  } while (0)

using v8::Array;
using v8::BackingStore;
using v8::BigInt;
using v8::CFunction;
using v8::Context;
using v8::Exception;
using v8::FastApiCallbackOptions;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Object;
using v8::Signature;
using v8::String;
using v8::Uint32;
using v8::Value;
using v8::WasmMemoryObject;

static MaybeLocal<Value> WASIException(Local<Context> context,
                                       int errorno,
                                       const char* syscall) {
  Isolate* isolate = context->GetIsolate();
  Environment* env = Environment::GetCurrent(context);
  CHECK_NOT_NULL(env);
  const char* err_name = uvwasi_embedder_err_code_to_string(errorno);
  Local<String> js_code = OneByteString(isolate, err_name);
  Local<String> js_syscall = OneByteString(isolate, syscall);
  Local<String> js_msg = js_code;
  js_msg =
      String::Concat(isolate, js_msg, FIXED_ONE_BYTE_STRING(isolate, ", "));
  js_msg = String::Concat(isolate, js_msg, js_syscall);
  Local<Object> e;
  if (!Exception::Error(js_msg)->ToObject(context).ToLocal(&e))
    return MaybeLocal<Value>();

  if (e->Set(context,
             env->errno_string(),
             Integer::New(isolate, errorno)).IsNothing() ||
      e->Set(context, env->code_string(), js_code).IsNothing() ||
      e->Set(context, env->syscall_string(), js_syscall).IsNothing()) {
    return MaybeLocal<Value>();
  }

  return e;
}


WASI::WASI(Environment* env,
           Local<Object> object,
           uvwasi_options_t* options) : BaseObject(env, object) {
  MakeWeak();
  alloc_info_ = MakeAllocator();
  options->allocator = &alloc_info_;
  int err = uvwasi_init(&uvw_, options);
  if (err != UVWASI_ESUCCESS) {
    Local<Value> exception;
    if (!WASIException(env->context(), err, "uvwasi_init").ToLocal(&exception))
      return;

    env->isolate()->ThrowException(exception);
  }
}


WASI::~WASI() {
  uvwasi_destroy(&uvw_);
  CHECK_EQ(current_uvwasi_memory_, 0);
}

void WASI::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("memory", memory_);
  tracker->TrackFieldWithSize("uvwasi_memory", current_uvwasi_memory_);
}

void WASI::CheckAllocatedSize(size_t previous_size) const {
  CHECK_GE(current_uvwasi_memory_, previous_size);
}

void WASI::IncreaseAllocatedSize(size_t size) {
  current_uvwasi_memory_ += size;
}

void WASI::DecreaseAllocatedSize(size_t size) {
  current_uvwasi_memory_ -= size;
}

void WASI::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  CHECK_EQ(args.Length(), 4);
  CHECK(args[0]->IsArray());
  CHECK(args[1]->IsArray());
  CHECK(args[2]->IsArray());
  CHECK(args[3]->IsArray());

  Environment* env = Environment::GetCurrent(args);
  Local<Context> context = env->context();
  Local<Array> argv = args[0].As<Array>();
  const uint32_t argc = argv->Length();
  uvwasi_options_t options;

  uvwasi_options_init(&options);

  Local<Array> stdio = args[3].As<Array>();
  CHECK_EQ(stdio->Length(), 3);
  options.in = stdio->Get(context, 0).ToLocalChecked()->
    Int32Value(context).FromJust();
  options.out = stdio->Get(context, 1).ToLocalChecked()->
    Int32Value(context).FromJust();
  options.err = stdio->Get(context, 2).ToLocalChecked()->
    Int32Value(context).FromJust();

  options.fd_table_size = 3;
  options.argc = argc;
  options.argv =
    const_cast<const char**>(argc == 0 ? nullptr : new char*[argc]);

  for (uint32_t i = 0; i < argc; i++) {
    auto arg = argv->Get(context, i).ToLocalChecked();
    CHECK(arg->IsString());
    node::Utf8Value str(env->isolate(), arg);
    options.argv[i] = strdup(*str);
    CHECK_NOT_NULL(options.argv[i]);
  }

  Local<Array> env_pairs = args[1].As<Array>();
  const uint32_t envc = env_pairs->Length();
  options.envp = const_cast<const char**>(new char*[envc + 1]);
  for (uint32_t i = 0; i < envc; i++) {
    auto pair = env_pairs->Get(context, i).ToLocalChecked();
    CHECK(pair->IsString());
    node::Utf8Value str(env->isolate(), pair);
    options.envp[i] = strdup(*str);
    CHECK_NOT_NULL(options.envp[i]);
  }
  options.envp[envc] = nullptr;

  Local<Array> preopens = args[2].As<Array>();
  CHECK_EQ(preopens->Length() % 2, 0);
  options.preopenc = preopens->Length() / 2;
  options.preopens = Calloc<uvwasi_preopen_t>(options.preopenc);
  int index = 0;
  for (uint32_t i = 0; i < preopens->Length(); i += 2) {
    auto mapped = preopens->Get(context, i).ToLocalChecked();
    auto real = preopens->Get(context, i + 1).ToLocalChecked();
    CHECK(mapped->IsString());
    CHECK(real->IsString());
    node::Utf8Value mapped_path(env->isolate(), mapped);
    node::Utf8Value real_path(env->isolate(), real);
    options.preopens[index].mapped_path = strdup(*mapped_path);
    CHECK_NOT_NULL(options.preopens[index].mapped_path);
    options.preopens[index].real_path = strdup(*real_path);
    CHECK_NOT_NULL(options.preopens[index].real_path);
    index++;
  }

  new WASI(env, args.This(), &options);

  if (options.argv != nullptr) {
    for (uint32_t i = 0; i < argc; i++)
      free(const_cast<char*>(options.argv[i]));
    delete[] options.argv;
  }

  for (uint32_t i = 0; options.envp[i]; i++)
    free(const_cast<char*>(options.envp[i]));
  delete[] options.envp;

  if (options.preopens != nullptr) {
    for (uint32_t i = 0; i < options.preopenc; i++) {
      free(const_cast<char*>(options.preopens[i].mapped_path));
      free(const_cast<char*>(options.preopens[i].real_path));
    }

    free(options.preopens);
  }
}

template <typename FT, FT F, typename R, typename... Args>
void WASI::WasiFunction<FT, F, R, Args...>::SetFunction(
    Environment* env, const char* name, Local<FunctionTemplate> tmpl) {
  auto c_function = CFunction::Make(FastCallback);
  Local<FunctionTemplate> t =
      v8::FunctionTemplate::New(env->isolate(),
                                SlowCallback,
                                Local<Value>(),
                                Local<Signature>(),
                                sizeof...(Args),
                                v8::ConstructorBehavior::kThrow,
                                v8::SideEffectType::kHasSideEffect,
                                &c_function);
  const v8::NewStringType type = v8::NewStringType::kInternalized;
  v8::Local<v8::String> name_string =
      v8::String::NewFromUtf8(env->isolate(), name, type).ToLocalChecked();
  tmpl->PrototypeTemplate()->Set(name_string, t);
  t->SetClassName(name_string);
}

template <typename FT, FT F, typename R, typename... Args>
R WASI::WasiFunction<FT, F, R, Args...>::FastCallback(
    Local<Object> receiver, Args... args, FastApiCallbackOptions& options) {
  WASI* wasi = reinterpret_cast<WASI*>(BaseObject::FromJSObject(receiver));
  if (UNLIKELY(wasi == nullptr)) return UVWASI_EINVAL;

  if (UNLIKELY(options.wasm_memory == nullptr)) {
    // fallback to slow path which to throw an error about missing memory.
    options.fallback = true;
    return UVWASI_EINVAL;
  }
  uint8_t* memory = nullptr;
  CHECK(LIKELY(options.wasm_memory->getStorageIfAligned(&memory)));

  return F(*wasi,
           {reinterpret_cast<char*>(memory), options.wasm_memory->length()},
           args...);
}

namespace {
template <typename VT>
static bool CheckType(Local<Value> v);

template <typename VT>
static VT ConvertType(Local<Value> V);

template <>
bool CheckType<uint32_t>(Local<Value> value) {
  return value->IsUint32();
}

template <>
uint32_t ConvertType(Local<Value> value) {
  return value.As<Uint32>()->Value();
}

template <>
bool CheckType<uint64_t>(Local<Value> value) {
  return value->IsBigInt();
}

template <>
uint64_t ConvertType(Local<Value> value) {
  Local<BigInt> js_value = value.As<BigInt>();
  bool lossless;
  return js_value->Uint64Value(&lossless);
}

template <>
bool CheckType<int64_t>(Local<Value> value) {
  return value->IsBigInt();
}

template <>
int64_t ConvertType(Local<Value> value) {
  Local<BigInt> js_value = value.As<BigInt>();
  bool lossless;
  return js_value->Int64Value(&lossless);
}

template <typename T>
bool CheckTypes(const FunctionCallbackInfo<Value>& info, int i, T) {
  return CheckType<T>(info[i]);
}

template <typename T, typename... Ts>
bool CheckTypes(const FunctionCallbackInfo<Value>& info,
                int i,
                T arg,
                Ts... args) {
  if (!CheckTypes<T>(info, i, arg)) return false;
  return CheckTypes<Ts...>(info, i + 1, args...);
}

template <typename... Args>
bool CheckTypes(const FunctionCallbackInfo<Value>& info) {
  return CheckTypes<Args...>(info, 0, Args()...);
}

template <>
bool CheckTypes(const FunctionCallbackInfo<Value>& info) {
  return true;
}

}  // namespace

template <typename FT, FT F, typename R, typename... Args>
template <std::size_t... Indices>
void WASI::WasiFunction<FT, F, R, Args...>::InnerSlowCallback(
    std::index_sequence<Indices...>, const FunctionCallbackInfo<Value>& args) {
  if (args.Length() != sizeof...(Args)) {
    args.GetReturnValue().Set(UVWASI_EINVAL);
    return;
  }
  if (!CheckTypes<Args...>(args)) {
    args.GetReturnValue().Set(UVWASI_EINVAL);
    return;
  }

  WASI* wasi;
  ASSIGN_OR_RETURN_UNWRAP(&wasi, args.This());
  if (wasi->memory_.IsEmpty()) {
    THROW_ERR_WASI_NOT_STARTED(Environment::GetCurrent(args));
    return;
  }

  Local<WasmMemoryObject> memory = PersistentToLocal::Strong(wasi->memory_);
  std::shared_ptr<BackingStore> backing_store =
      memory->Buffer()->GetBackingStore();
  size_t mem_size = backing_store->ByteLength();
  char* mem_data = static_cast<char*>(backing_store->Data());
  CHECK(mem_data != nullptr);

  args.GetReturnValue().Set(
      F(*wasi, {mem_data, mem_size}, ConvertType<Args>(args[Indices])...));
}

template <typename FT, FT F, typename R, typename... Args>
void WASI::WasiFunction<FT, F, R, Args...>::SlowCallback(
    const FunctionCallbackInfo<Value>& args) {
  InnerSlowCallback(std::make_index_sequence<sizeof...(Args)>{}, args);
}

template <typename FT, FT F, typename R, typename... Args>
static void SetFunction(R (*f)(WASI&, WasmMemory, Args...),
                        Environment* env,
                        const char* name,
                        Local<FunctionTemplate> tmpl) {
  WASI::WasiFunction<FT, F, R, Args...>::SetFunction(env, name, tmpl);
}

uint32_t WASI::ArgsGet(WASI& wasi,
                       WasmMemory memory,
                       uint32_t argv_offset,
                       uint32_t argv_buf_offset) {
  Debug(wasi, "args_get(%d, %d)\n", argv_offset, argv_buf_offset);

  CHECK_BOUNDS_OR_RETURN2(
      memory.size, argv_buf_offset, wasi.uvw_.argv_buf_size);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, argv_offset, wasi.uvw_.argc * UVWASI_SERDES_SIZE_uint32_t);
  std::vector<char*> argv(wasi.uvw_.argc);
  char* argv_buf = &memory.data[argv_buf_offset];
  uvwasi_errno_t err = uvwasi_args_get(&wasi.uvw_, argv.data(), argv_buf);

  if (err == UVWASI_ESUCCESS) {
    for (size_t i = 0; i < wasi.uvw_.argc; i++) {
      uint32_t offset =
          static_cast<uint32_t>(argv_buf_offset + (argv[i] - argv[0]));
      uvwasi_serdes_write_uint32_t(
          memory.data, argv_offset + (i * UVWASI_SERDES_SIZE_uint32_t), offset);
    }
  }

  return err;
}

uint32_t WASI::ArgsSizesGet(WASI& wasi,
                            WasmMemory memory,
                            uint32_t argc_offset,
                            uint32_t argv_buf_offset) {
  Debug(wasi, "args_sizes_get(%d, %d)\n", argc_offset, argv_buf_offset);
  CHECK_BOUNDS_OR_RETURN2(memory.size, argc_offset, UVWASI_SERDES_SIZE_size_t);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, argv_buf_offset, UVWASI_SERDES_SIZE_size_t);
  uvwasi_size_t argc;
  uvwasi_size_t argv_buf_size;
  uvwasi_errno_t err = uvwasi_args_sizes_get(&wasi.uvw_, &argc, &argv_buf_size);
  if (err == UVWASI_ESUCCESS) {
    uvwasi_serdes_write_size_t(memory.data, argc_offset, argc);
    uvwasi_serdes_write_size_t(memory.data, argv_buf_offset, argv_buf_size);
  }

  return err;
}

uint32_t WASI::ClockResGet(WASI& wasi,
                           WasmMemory memory,
                           uint32_t clock_id,
                           uint32_t resolution_ptr) {
  Debug(wasi, "clock_res_get(%d, %d)\n", clock_id, resolution_ptr);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, resolution_ptr, UVWASI_SERDES_SIZE_timestamp_t);
  uvwasi_timestamp_t resolution;
  uvwasi_errno_t err = uvwasi_clock_res_get(&wasi.uvw_, clock_id, &resolution);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_timestamp_t(memory.data, resolution_ptr, resolution);

  return err;
}

uint32_t WASI::ClockTimeGet(WASI& wasi,
                            WasmMemory memory,
                            uint32_t clock_id,
                            uint64_t precision,
                            uint32_t time_ptr) {
  Debug(wasi, "clock_time_get(%d, %d, %d)\n", clock_id, precision, time_ptr);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, time_ptr, UVWASI_SERDES_SIZE_timestamp_t);
  uvwasi_timestamp_t time;
  uvwasi_errno_t err =
      uvwasi_clock_time_get(&wasi.uvw_, clock_id, precision, &time);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_timestamp_t(memory.data, time_ptr, time);

  return err;
}

uint32_t WASI::EnvironGet(WASI& wasi,
                          WasmMemory memory,
                          uint32_t environ_offset,
                          uint32_t environ_buf_offset) {
  Debug(wasi, "environ_get(%d, %d)\n", environ_offset, environ_buf_offset);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, environ_buf_offset, wasi.uvw_.env_buf_size);
  CHECK_BOUNDS_OR_RETURN2(memory.size,
                          environ_offset,
                          wasi.uvw_.envc * UVWASI_SERDES_SIZE_uint32_t);
  std::vector<char*> environment(wasi.uvw_.envc);
  char* environ_buf = &memory.data[environ_buf_offset];
  uvwasi_errno_t err =
      uvwasi_environ_get(&wasi.uvw_, environment.data(), environ_buf);

  if (err == UVWASI_ESUCCESS) {
    for (size_t i = 0; i < wasi.uvw_.envc; i++) {
      uint32_t offset = static_cast<uint32_t>(
          environ_buf_offset + (environment[i] - environment[0]));

      uvwasi_serdes_write_uint32_t(
          memory.data,
          environ_offset + (i * UVWASI_SERDES_SIZE_uint32_t),
          offset);
    }
  }

  return err;
}

uint32_t WASI::EnvironSizesGet(WASI& wasi,
                               WasmMemory memory,
                               uint32_t envc_offset,
                               uint32_t env_buf_offset) {
  Debug(wasi, "environ_sizes_get(%d, %d)\n", envc_offset, env_buf_offset);
  CHECK_BOUNDS_OR_RETURN2(memory.size, envc_offset, UVWASI_SERDES_SIZE_size_t);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, env_buf_offset, UVWASI_SERDES_SIZE_size_t);
  uvwasi_size_t envc;
  uvwasi_size_t env_buf_size;
  uvwasi_errno_t err =
      uvwasi_environ_sizes_get(&wasi.uvw_, &envc, &env_buf_size);
  if (err == UVWASI_ESUCCESS) {
    uvwasi_serdes_write_size_t(memory.data, envc_offset, envc);
    uvwasi_serdes_write_size_t(memory.data, env_buf_offset, env_buf_size);
  }

  return err;
}

uint32_t WASI::FdAdvise(WASI& wasi,
                        WasmMemory,
                        uint32_t fd,
                        uint64_t offset,
                        uint64_t len,
                        uint32_t advice) {
  Debug(wasi, "fd_advise(%d, %d, %d, %d)\n", fd, offset, len, advice);
  return uvwasi_fd_advise(&wasi.uvw_, fd, offset, len, advice);
}

uint32_t WASI::FdAllocate(
    WASI& wasi, WasmMemory, uint32_t fd, uint64_t offset, uint64_t len) {
  Debug(wasi, "fd_allocate(%d, %d, %d)\n", fd, offset, len);
  return uvwasi_fd_allocate(&wasi.uvw_, fd, offset, len);
}

uint32_t WASI::FdClose(WASI& wasi, WasmMemory, uint32_t fd) {
  Debug(wasi, "fd_close(%d)\n", fd);
  return uvwasi_fd_close(&wasi.uvw_, fd);
}

uint32_t WASI::FdDatasync(WASI& wasi, WasmMemory, uint32_t fd) {
  Debug(wasi, "fd_datasync(%d)\n", fd);
  return uvwasi_fd_datasync(&wasi.uvw_, fd);
}

uint32_t WASI::FdFdstatGet(WASI& wasi,
                           WasmMemory memory,
                           uint32_t fd,
                           uint32_t buf) {
  Debug(wasi, "fd_fdstat_get(%d, %d)\n", fd, buf);
  CHECK_BOUNDS_OR_RETURN2(memory.size, buf, UVWASI_SERDES_SIZE_fdstat_t);
  uvwasi_fdstat_t stats;
  uvwasi_errno_t err = uvwasi_fd_fdstat_get(&wasi.uvw_, fd, &stats);

  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_fdstat_t(memory.data, buf, &stats);

  return err;
}

uint32_t WASI::FdFdstatSetFlags(WASI& wasi,
                                WasmMemory,
                                uint32_t fd,
                                uint32_t flags) {
  Debug(wasi, "fd_fdstat_set_flags(%d, %d)\n", fd, flags);
  return uvwasi_fd_fdstat_set_flags(&wasi.uvw_, fd, flags);
}

uint32_t WASI::FdFdstatSetRights(WASI& wasi,
                                 WasmMemory,
                                 uint32_t fd,
                                 uint64_t fs_rights_base,
                                 uint64_t fs_rights_inheriting) {
  Debug(wasi,
        "fd_fdstat_set_rights(%d, %d, %d)\n",
        fd,
        fs_rights_base,
        fs_rights_inheriting);
  return uvwasi_fd_fdstat_set_rights(
      &wasi.uvw_, fd, fs_rights_base, fs_rights_inheriting);
}

uint32_t WASI::FdFilestatGet(WASI& wasi,
                             WasmMemory memory,
                             uint32_t fd,
                             uint32_t buf) {
  Debug(wasi, "fd_filestat_get(%d, %d)\n", fd, buf);
  CHECK_BOUNDS_OR_RETURN2(memory.size, buf, UVWASI_SERDES_SIZE_filestat_t);
  uvwasi_filestat_t stats;
  uvwasi_errno_t err = uvwasi_fd_filestat_get(&wasi.uvw_, fd, &stats);

  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_filestat_t(memory.data, buf, &stats);

  return err;
}

uint32_t WASI::FdFilestatSetSize(WASI& wasi,
                                 WasmMemory,
                                 uint32_t fd,
                                 uint64_t st_size) {
  Debug(wasi, "fd_filestat_set_size(%d, %d)\n", fd, st_size);
  return uvwasi_fd_filestat_set_size(&wasi.uvw_, fd, st_size);
}

uint32_t WASI::FdFilestatSetTimes(WASI& wasi,
                                  WasmMemory,
                                  uint32_t fd,
                                  uint64_t st_atim,
                                  uint64_t st_mtim,
                                  uint32_t fst_flags) {
  Debug(wasi,
        "fd_filestat_set_times(%d, %d, %d, %d)\n",
        fd,
        st_atim,
        st_mtim,
        fst_flags);
  return uvwasi_fd_filestat_set_times(
      &wasi.uvw_, fd, st_atim, st_mtim, fst_flags);
}

uint32_t WASI::FdPread(WASI& wasi,
                       WasmMemory memory,
                       uint32_t fd,
                       uint32_t iovs_ptr,
                       uint32_t iovs_len,
                       uint64_t offset,
                       uint32_t nread_ptr) {
  Debug(wasi,
        "uvwasi_fd_pread(%d, %d, %d, %d, %d)\n",
        fd,
        iovs_ptr,
        iovs_len,
        offset,
        nread_ptr);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, iovs_ptr, iovs_len * UVWASI_SERDES_SIZE_iovec_t);
  CHECK_BOUNDS_OR_RETURN2(memory.size, nread_ptr, UVWASI_SERDES_SIZE_size_t);
  std::vector<uvwasi_iovec_t> iovs(iovs_len);
  uvwasi_errno_t err;

  err = uvwasi_serdes_readv_iovec_t(
      memory.data, memory.size, iovs_ptr, iovs.data(), iovs_len);
  if (err != UVWASI_ESUCCESS) {
    return err;
  }

  uvwasi_size_t nread;
  err = uvwasi_fd_pread(&wasi.uvw_, fd, iovs.data(), iovs_len, offset, &nread);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_size_t(memory.data, nread_ptr, nread);

  return err;
}

uint32_t WASI::FdPrestatGet(WASI& wasi,
                            WasmMemory memory,
                            uint32_t fd,
                            uint32_t buf) {
  Debug(wasi, "fd_prestat_get(%d, %d)\n", fd, buf);
  CHECK_BOUNDS_OR_RETURN2(memory.size, buf, UVWASI_SERDES_SIZE_prestat_t);
  uvwasi_prestat_t prestat;
  uvwasi_errno_t err = uvwasi_fd_prestat_get(&wasi.uvw_, fd, &prestat);

  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_prestat_t(memory.data, buf, &prestat);

  return err;
}

uint32_t WASI::FdPrestatDirName(WASI& wasi,
                                WasmMemory memory,
                                uint32_t fd,
                                uint32_t path_ptr,
                                uint32_t path_len) {
  Debug(wasi, "fd_prestat_dir_name(%d, %d, %d)\n", fd, path_ptr, path_len);
  CHECK_BOUNDS_OR_RETURN2(memory.size, path_ptr, path_len);
  return uvwasi_fd_prestat_dir_name(
      &wasi.uvw_, fd, &memory.data[path_ptr], path_len);
}

uint32_t WASI::FdPwrite(WASI& wasi,
                        WasmMemory memory,
                        uint32_t fd,
                        uint32_t iovs_ptr,
                        uint32_t iovs_len,
                        uint64_t offset,
                        uint32_t nwritten_ptr) {
  Debug(wasi,
        "uvwasi_fd_pwrite(%d, %d, %d, %d, %d)\n",
        fd,
        iovs_ptr,
        iovs_len,
        offset,
        nwritten_ptr);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, iovs_ptr, iovs_len * UVWASI_SERDES_SIZE_ciovec_t);
  CHECK_BOUNDS_OR_RETURN2(memory.size, nwritten_ptr, UVWASI_SERDES_SIZE_size_t);
  std::vector<uvwasi_ciovec_t> iovs(iovs_len);
  uvwasi_errno_t err;

  err = uvwasi_serdes_readv_ciovec_t(
      memory.data, memory.size, iovs_ptr, iovs.data(), iovs_len);
  if (err != UVWASI_ESUCCESS) {
    return err;
  }

  uvwasi_size_t nwritten;
  err = uvwasi_fd_pwrite(
      &wasi.uvw_, fd, iovs.data(), iovs_len, offset, &nwritten);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_size_t(memory.data, nwritten_ptr, nwritten);

  return err;
}

void WASI::FdRead(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t iovs_ptr;
  uint32_t iovs_len;
  uint32_t nread_ptr;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 4);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, iovs_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, iovs_len);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, nread_ptr);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi, "fd_read(%d, %d, %d, %d)\n", fd, iovs_ptr, iovs_len, nread_ptr);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         iovs_ptr,
                         iovs_len * UVWASI_SERDES_SIZE_iovec_t);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, nread_ptr, UVWASI_SERDES_SIZE_size_t);
  std::vector<uvwasi_iovec_t> iovs(iovs_len);
  uvwasi_errno_t err;

  err = uvwasi_serdes_readv_iovec_t(memory,
                                    mem_size,
                                    iovs_ptr,
                                    iovs.data(),
                                    iovs_len);
  if (err != UVWASI_ESUCCESS) {
    args.GetReturnValue().Set(err);
    return;
  }

  uvwasi_size_t nread;
  err = uvwasi_fd_read(&wasi->uvw_, fd, iovs.data(), iovs_len, &nread);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_size_t(memory, nread_ptr, nread);

  args.GetReturnValue().Set(err);
}


void WASI::FdReaddir(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t buf_ptr;
  uint32_t buf_len;
  uint64_t cookie;
  uint32_t bufused_ptr;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 5);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, buf_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, buf_len);
  UNWRAP_BIGINT_OR_RETURN(args, args[3], Uint64, cookie);
  CHECK_TO_TYPE_OR_RETURN(args, args[4], Uint32, bufused_ptr);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "uvwasi_fd_readdir(%d, %d, %d, %d, %d)\n",
        fd,
        buf_ptr,
        buf_len,
        cookie,
        bufused_ptr);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, buf_ptr, buf_len);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         bufused_ptr,
                         UVWASI_SERDES_SIZE_size_t);
  uvwasi_size_t bufused;
  uvwasi_errno_t err = uvwasi_fd_readdir(&wasi->uvw_,
                                         fd,
                                         &memory[buf_ptr],
                                         buf_len,
                                         cookie,
                                         &bufused);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_size_t(memory, bufused_ptr, bufused);

  args.GetReturnValue().Set(err);
}


void WASI::FdRenumber(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t from;
  uint32_t to;
  RETURN_IF_BAD_ARG_COUNT(args, 2);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, from);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, to);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi, "fd_renumber(%d, %d)\n", from, to);
  uvwasi_errno_t err = uvwasi_fd_renumber(&wasi->uvw_, from, to);
  args.GetReturnValue().Set(err);
}

uint32_t WASI::FdSeek(WASI& wasi,
                      WasmMemory memory,
                      uint32_t fd,
                      int64_t offset,
                      uint32_t whence,
                      uint32_t newoffset_ptr) {
  Debug(&wasi, "fd_seek(%d, %d, %d, %d)\n", fd, offset, whence, newoffset_ptr);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, newoffset_ptr, UVWASI_SERDES_SIZE_filesize_t);
  uvwasi_filesize_t newoffset;
  uvwasi_errno_t err =
      uvwasi_fd_seek(&wasi.uvw_, fd, offset, whence, &newoffset);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_filesize_t(memory.data, newoffset_ptr, newoffset);

  return err;
}

void WASI::FdSync(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  RETURN_IF_BAD_ARG_COUNT(args, 1);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi, "fd_sync(%d)\n", fd);
  uvwasi_errno_t err = uvwasi_fd_sync(&wasi->uvw_, fd);
  args.GetReturnValue().Set(err);
}


void WASI::FdTell(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t offset_ptr;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 2);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, offset_ptr);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi, "fd_tell(%d, %d)\n", fd, offset_ptr);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         offset_ptr,
                         UVWASI_SERDES_SIZE_filesize_t);
  uvwasi_filesize_t offset;
  uvwasi_errno_t err = uvwasi_fd_tell(&wasi->uvw_, fd, &offset);

  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_filesize_t(memory, offset_ptr, offset);

  args.GetReturnValue().Set(err);
}


void WASI::FdWrite(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t iovs_ptr;
  uint32_t iovs_len;
  uint32_t nwritten_ptr;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 4);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, iovs_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, iovs_len);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, nwritten_ptr);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "fd_write(%d, %d, %d, %d)\n",
        fd,
        iovs_ptr,
        iovs_len,
        nwritten_ptr);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         iovs_ptr,
                         iovs_len * UVWASI_SERDES_SIZE_ciovec_t);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         nwritten_ptr,
                         UVWASI_SERDES_SIZE_size_t);
  std::vector<uvwasi_ciovec_t> iovs(iovs_len);
  uvwasi_errno_t err;

  err = uvwasi_serdes_readv_ciovec_t(memory,
                                     mem_size,
                                     iovs_ptr,
                                     iovs.data(),
                                     iovs_len);
  if (err != UVWASI_ESUCCESS) {
    args.GetReturnValue().Set(err);
    return;
  }

  uvwasi_size_t nwritten;
  err = uvwasi_fd_write(&wasi->uvw_, fd, iovs.data(), iovs_len, &nwritten);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_size_t(memory, nwritten_ptr, nwritten);

  args.GetReturnValue().Set(err);
}


void WASI::PathCreateDirectory(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t path_ptr;
  uint32_t path_len;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 3);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, path_len);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi, "path_create_directory(%d, %d, %d)\n", fd, path_ptr, path_len);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, path_ptr, path_len);
  uvwasi_errno_t err = uvwasi_path_create_directory(&wasi->uvw_,
                                                    fd,
                                                    &memory[path_ptr],
                                                    path_len);
  args.GetReturnValue().Set(err);
}


void WASI::PathFilestatGet(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t flags;
  uint32_t path_ptr;
  uint32_t path_len;
  uint32_t buf_ptr;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 5);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, flags);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, path_len);
  CHECK_TO_TYPE_OR_RETURN(args, args[4], Uint32, buf_ptr);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "path_filestat_get(%d, %d, %d)\n",
        fd,
        path_ptr,
        path_len);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, path_ptr, path_len);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         buf_ptr,
                         UVWASI_SERDES_SIZE_filestat_t);
  uvwasi_filestat_t stats;
  uvwasi_errno_t err = uvwasi_path_filestat_get(&wasi->uvw_,
                                                fd,
                                                flags,
                                                &memory[path_ptr],
                                                path_len,
                                                &stats);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_filestat_t(memory, buf_ptr, &stats);

  args.GetReturnValue().Set(err);
}


void WASI::PathFilestatSetTimes(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t flags;
  uint32_t path_ptr;
  uint32_t path_len;
  uint64_t st_atim;
  uint64_t st_mtim;
  uint16_t fst_flags;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 7);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, flags);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, path_len);
  UNWRAP_BIGINT_OR_RETURN(args, args[4], Uint64, st_atim);
  UNWRAP_BIGINT_OR_RETURN(args, args[5], Uint64, st_mtim);
  CHECK_TO_TYPE_OR_RETURN(args, args[6], Uint32, fst_flags);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "path_filestat_set_times(%d, %d, %d, %d, %d, %d, %d)\n",
        fd,
        flags,
        path_ptr,
        path_len,
        st_atim,
        st_mtim,
        fst_flags);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, path_ptr, path_len);
  uvwasi_errno_t err = uvwasi_path_filestat_set_times(&wasi->uvw_,
                                                      fd,
                                                      flags,
                                                      &memory[path_ptr],
                                                      path_len,
                                                      st_atim,
                                                      st_mtim,
                                                      fst_flags);
  args.GetReturnValue().Set(err);
}


void WASI::PathLink(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t old_fd;
  uint32_t old_flags;
  uint32_t old_path_ptr;
  uint32_t old_path_len;
  uint32_t new_fd;
  uint32_t new_path_ptr;
  uint32_t new_path_len;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 7);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, old_fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, old_flags);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, old_path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, old_path_len);
  CHECK_TO_TYPE_OR_RETURN(args, args[4], Uint32, new_fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[5], Uint32, new_path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[6], Uint32, new_path_len);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "path_link(%d, %d, %d, %d, %d, %d, %d)\n",
        old_fd,
        old_flags,
        old_path_ptr,
        old_path_len,
        new_fd,
        new_path_ptr,
        new_path_len);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, old_path_ptr, old_path_len);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, new_path_ptr, new_path_len);
  uvwasi_errno_t err = uvwasi_path_link(&wasi->uvw_,
                                        old_fd,
                                        old_flags,
                                        &memory[old_path_ptr],
                                        old_path_len,
                                        new_fd,
                                        &memory[new_path_ptr],
                                        new_path_len);
  args.GetReturnValue().Set(err);
}


void WASI::PathOpen(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t dirfd;
  uint32_t dirflags;
  uint32_t path_ptr;
  uint32_t path_len;
  uint32_t o_flags;
  uint64_t fs_rights_base;
  uint64_t fs_rights_inheriting;
  uint32_t fs_flags;
  uint32_t fd_ptr;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 9);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, dirfd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, dirflags);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, path_len);
  CHECK_TO_TYPE_OR_RETURN(args, args[4], Uint32, o_flags);
  UNWRAP_BIGINT_OR_RETURN(args, args[5], Uint64, fs_rights_base);
  UNWRAP_BIGINT_OR_RETURN(args, args[6], Uint64, fs_rights_inheriting);
  CHECK_TO_TYPE_OR_RETURN(args, args[7], Uint32, fs_flags);
  CHECK_TO_TYPE_OR_RETURN(args, args[8], Uint32, fd_ptr);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "path_open(%d, %d, %d, %d, %d, %d, %d, %d, %d)\n",
        dirfd,
        dirflags,
        path_ptr,
        path_len,
        o_flags,
        fs_rights_base,
        fs_rights_inheriting,
        fs_flags,
        fd_ptr);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, path_ptr, path_len);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, fd_ptr, UVWASI_SERDES_SIZE_fd_t);
  uvwasi_fd_t fd;
  uvwasi_errno_t err = uvwasi_path_open(&wasi->uvw_,
                                        dirfd,
                                        dirflags,
                                        &memory[path_ptr],
                                        path_len,
                                        static_cast<uvwasi_oflags_t>(o_flags),
                                        fs_rights_base,
                                        fs_rights_inheriting,
                                        static_cast<uvwasi_fdflags_t>(fs_flags),
                                        &fd);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_size_t(memory, fd_ptr, fd);

  args.GetReturnValue().Set(err);
}


void WASI::PathReadlink(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t path_ptr;
  uint32_t path_len;
  uint32_t buf_ptr;
  uint32_t buf_len;
  uint32_t bufused_ptr;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 6);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, path_len);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, buf_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[4], Uint32, buf_len);
  CHECK_TO_TYPE_OR_RETURN(args, args[5], Uint32, bufused_ptr);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "path_readlink(%d, %d, %d, %d, %d, %d)\n",
        fd,
        path_ptr,
        path_len,
        buf_ptr,
        buf_len,
        bufused_ptr);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, path_ptr, path_len);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, buf_ptr, buf_len);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         bufused_ptr,
                         UVWASI_SERDES_SIZE_size_t);
  uvwasi_size_t bufused;
  uvwasi_errno_t err = uvwasi_path_readlink(&wasi->uvw_,
                                            fd,
                                            &memory[path_ptr],
                                            path_len,
                                            &memory[buf_ptr],
                                            buf_len,
                                            &bufused);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_size_t(memory, bufused_ptr, bufused);

  args.GetReturnValue().Set(err);
}


void WASI::PathRemoveDirectory(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t path_ptr;
  uint32_t path_len;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 3);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, path_len);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi, "path_remove_directory(%d, %d, %d)\n", fd, path_ptr, path_len);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, path_ptr, path_len);
  uvwasi_errno_t err = uvwasi_path_remove_directory(&wasi->uvw_,
                                                    fd,
                                                    &memory[path_ptr],
                                                    path_len);
  args.GetReturnValue().Set(err);
}


void WASI::PathRename(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t old_fd;
  uint32_t old_path_ptr;
  uint32_t old_path_len;
  uint32_t new_fd;
  uint32_t new_path_ptr;
  uint32_t new_path_len;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 6);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, old_fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, old_path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, old_path_len);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, new_fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[4], Uint32, new_path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[5], Uint32, new_path_len);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "path_rename(%d, %d, %d, %d, %d, %d)\n",
        old_fd,
        old_path_ptr,
        old_path_len,
        new_fd,
        new_path_ptr,
        new_path_len);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, old_path_ptr, old_path_len);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, new_path_ptr, new_path_len);
  uvwasi_errno_t err = uvwasi_path_rename(&wasi->uvw_,
                                          old_fd,
                                          &memory[old_path_ptr],
                                          old_path_len,
                                          new_fd,
                                          &memory[new_path_ptr],
                                          new_path_len);
  args.GetReturnValue().Set(err);
}


void WASI::PathSymlink(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t old_path_ptr;
  uint32_t old_path_len;
  uint32_t fd;
  uint32_t new_path_ptr;
  uint32_t new_path_len;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 5);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, old_path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, old_path_len);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, new_path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[4], Uint32, new_path_len);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "path_symlink(%d, %d, %d, %d, %d)\n",
        old_path_ptr,
        old_path_len,
        fd,
        new_path_ptr,
        new_path_len);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, old_path_ptr, old_path_len);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, new_path_ptr, new_path_len);
  uvwasi_errno_t err = uvwasi_path_symlink(&wasi->uvw_,
                                           &memory[old_path_ptr],
                                           old_path_len,
                                           fd,
                                           &memory[new_path_ptr],
                                           new_path_len);
  args.GetReturnValue().Set(err);
}


void WASI::PathUnlinkFile(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t fd;
  uint32_t path_ptr;
  uint32_t path_len;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 3);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, fd);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, path_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, path_len);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi, "path_unlink_file(%d, %d, %d)\n", fd, path_ptr, path_len);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args, mem_size, path_ptr, path_len);
  uvwasi_errno_t err = uvwasi_path_unlink_file(&wasi->uvw_,
                                               fd,
                                               &memory[path_ptr],
                                               path_len);
  args.GetReturnValue().Set(err);
}


void WASI::PollOneoff(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t in_ptr;
  uint32_t out_ptr;
  uint32_t nsubscriptions;
  uint32_t nevents_ptr;
  char* memory;
  size_t mem_size;
  RETURN_IF_BAD_ARG_COUNT(args, 4);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, in_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[1], Uint32, out_ptr);
  CHECK_TO_TYPE_OR_RETURN(args, args[2], Uint32, nsubscriptions);
  CHECK_TO_TYPE_OR_RETURN(args, args[3], Uint32, nevents_ptr);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi,
        "poll_oneoff(%d, %d, %d, %d)\n",
        in_ptr,
        out_ptr,
        nsubscriptions,
        nevents_ptr);
  GET_BACKING_STORE_OR_RETURN(wasi, args, &memory, &mem_size);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         in_ptr,
                         nsubscriptions * UVWASI_SERDES_SIZE_subscription_t);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         out_ptr,
                         nsubscriptions * UVWASI_SERDES_SIZE_event_t);
  CHECK_BOUNDS_OR_RETURN(args,
                         mem_size,
                         nevents_ptr,
                         UVWASI_SERDES_SIZE_size_t);
  std::vector<uvwasi_subscription_t> in(nsubscriptions);
  std::vector<uvwasi_event_t> out(nsubscriptions);

  for (uint32_t i = 0; i < nsubscriptions; ++i) {
    uvwasi_serdes_read_subscription_t(memory, in_ptr, &in[i]);
    in_ptr += UVWASI_SERDES_SIZE_subscription_t;
  }

  uvwasi_size_t nevents;
  uvwasi_errno_t err = uvwasi_poll_oneoff(&wasi->uvw_,
                                          in.data(),
                                          out.data(),
                                          nsubscriptions,
                                          &nevents);
  if (err == UVWASI_ESUCCESS) {
    uvwasi_serdes_write_size_t(memory, nevents_ptr, nevents);

    for (uint32_t i = 0; i < nsubscriptions; ++i) {
      uvwasi_serdes_write_event_t(memory, out_ptr, &out[i]);
      out_ptr += UVWASI_SERDES_SIZE_event_t;
    }
  }

  args.GetReturnValue().Set(err);
}


void WASI::ProcExit(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t code;
  RETURN_IF_BAD_ARG_COUNT(args, 1);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, code);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi, "proc_exit(%d)\n", code);
  args.GetReturnValue().Set(uvwasi_proc_exit(&wasi->uvw_, code));
}


void WASI::ProcRaise(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  uint32_t sig;
  RETURN_IF_BAD_ARG_COUNT(args, 1);
  CHECK_TO_TYPE_OR_RETURN(args, args[0], Uint32, sig);
  ASSIGN_INITIALIZED_OR_RETURN_UNWRAP(&wasi, args.This());
  Debug(wasi, "proc_raise(%d)\n", sig);
  uvwasi_errno_t err = uvwasi_proc_raise(&wasi->uvw_, sig);
  args.GetReturnValue().Set(err);
}

uint32_t WASI::RandomGet(WASI& wasi,
                         WasmMemory memory,
                         uint32_t buf_ptr,
                         uint32_t buf_len) {
  Debug(&wasi, "random_get(%d, %d)\n", buf_ptr, buf_len);
  CHECK_BOUNDS_OR_RETURN2(memory.size, buf_ptr, buf_len);
  return uvwasi_random_get(&wasi.uvw_, &memory.data[buf_ptr], buf_len);
}

uint32_t WASI::SchedYield(WASI& wasi, WasmMemory) {
  Debug(&wasi, "sched_yield()\n");
  return uvwasi_sched_yield(&wasi.uvw_);
}

uint32_t WASI::SockRecv(WASI& wasi,
                        WasmMemory memory,
                        uint32_t sock,
                        uint32_t ri_data_ptr,
                        uint32_t ri_data_len,
                        uint32_t ri_flags,
                        uint32_t ro_datalen_ptr,
                        uint32_t ro_flags_ptr) {
  Debug(wasi,
        "sock_recv(%d, %d, %d, %d, %d, %d)\n",
        sock,
        ri_data_ptr,
        ri_data_len,
        ri_flags,
        ro_datalen_ptr,
        ro_flags_ptr);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, ri_data_ptr, ri_data_len * UVWASI_SERDES_SIZE_iovec_t);
  CHECK_BOUNDS_OR_RETURN2(memory.size, ro_datalen_ptr, 4);
  CHECK_BOUNDS_OR_RETURN2(memory.size, ro_flags_ptr, 4);
  std::vector<uvwasi_iovec_t> ri_data(ri_data_len);
  uvwasi_errno_t err = uvwasi_serdes_readv_iovec_t(
      memory.data, memory.size, ri_data_ptr, ri_data.data(), ri_data_len);
  if (err != UVWASI_ESUCCESS) {
    return err;
  }

  uvwasi_size_t ro_datalen;
  uvwasi_roflags_t ro_flags;
  err = uvwasi_sock_recv(&wasi.uvw_,
                         sock,
                         ri_data.data(),
                         ri_data_len,
                         ri_flags,
                         &ro_datalen,
                         &ro_flags);
  if (err == UVWASI_ESUCCESS) {
    uvwasi_serdes_write_size_t(memory.data, ro_datalen_ptr, ro_datalen);
    uvwasi_serdes_write_roflags_t(memory.data, ro_flags_ptr, ro_flags);
  }

  return err;
}

uint32_t WASI::SockSend(WASI& wasi,
                        WasmMemory memory,
                        uint32_t sock,
                        uint32_t si_data_ptr,
                        uint32_t si_data_len,
                        uint32_t si_flags,
                        uint32_t so_datalen_ptr) {
  Debug(wasi,
        "sock_send(%d, %d, %d, %d, %d)\n",
        sock,
        si_data_ptr,
        si_data_len,
        si_flags,
        so_datalen_ptr);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, si_data_ptr, si_data_len * UVWASI_SERDES_SIZE_ciovec_t);
  CHECK_BOUNDS_OR_RETURN2(
      memory.size, so_datalen_ptr, UVWASI_SERDES_SIZE_size_t);
  std::vector<uvwasi_ciovec_t> si_data(si_data_len);
  uvwasi_errno_t err = uvwasi_serdes_readv_ciovec_t(
      memory.data, memory.size, si_data_ptr, si_data.data(), si_data_len);
  if (err != UVWASI_ESUCCESS) {
    return err;
  }

  uvwasi_size_t so_datalen;
  err = uvwasi_sock_send(
      &wasi.uvw_, sock, si_data.data(), si_data_len, si_flags, &so_datalen);
  if (err == UVWASI_ESUCCESS)
    uvwasi_serdes_write_size_t(memory.data, so_datalen_ptr, so_datalen);

  return err;
}

uint32_t WASI::SockShutdown(WASI& wasi,
                            WasmMemory,
                            uint32_t sock,
                            uint32_t how) {
  Debug(wasi, "sock_shutdown(%d, %d)\n", sock, how);
  return uvwasi_sock_shutdown(&wasi.uvw_, sock, how);
}

void WASI::_SetMemory(const FunctionCallbackInfo<Value>& args) {
  WASI* wasi;
  ASSIGN_OR_RETURN_UNWRAP(&wasi, args.This());
  CHECK_EQ(args.Length(), 1);
  if (!args[0]->IsWasmMemoryObject()) {
    return node::THROW_ERR_INVALID_ARG_TYPE(
        wasi->env(),
        "\"instance.exports.memory\" property must be a WebAssembly.Memory "
        "object");
  }
  wasi->memory_.Reset(wasi->env()->isolate(), args[0].As<WasmMemoryObject>());
}

static void Initialize(Local<Object> target,
                       Local<Value> unused,
                       Local<Context> context,
                       void* priv) {
  Environment* env = Environment::GetCurrent(context);

  Local<FunctionTemplate> tmpl = env->NewFunctionTemplate(WASI::New);
  tmpl->InstanceTemplate()->SetInternalFieldCount(WASI::kInternalFieldCount);
  tmpl->Inherit(BaseObject::GetConstructorTemplate(env));

#define V(F, name)                                                             \
  SetFunction<decltype(&WASI::F), WASI::F>(WASI::F, env, name, tmpl);

  V(ArgsGet, "args_get")
  V(ArgsSizesGet, "args_sizes_get")
  V(ClockResGet, "clock_res_get")
  V(ClockTimeGet, "clock_time_get")
  V(EnvironGet, "environ_get")
  V(EnvironSizesGet, "environ_sizes_get")
  V(FdAdvise, "fd_advise")
  V(FdAllocate, "fd_allocate")
  V(FdClose, "fd_close")
  V(FdDatasync, "fd_datasync")
  V(FdFdstatGet, "fd_fdstat_get")
  V(FdFdstatSetFlags, "fd_fdstat_set_flags")
  V(FdFdstatSetRights, "fd_fdstat_set_rights")
  V(FdFilestatGet, "fd_filestat_get")
  V(FdFilestatSetSize, "fd_filestat_set_size")
  V(FdFilestatSetTimes, "fd_filestat_set_times")
  V(FdPread, "fd_pread")
  V(FdPrestatGet, "fd_prestat_get")
  V(FdPrestatDirName, "fd_prestat_dir_name")
  V(FdPwrite, "fd_pwrite")
  env->SetProtoMethod(tmpl, "fd_read", WASI::FdRead);
  env->SetProtoMethod(tmpl, "fd_readdir", WASI::FdReaddir);
  env->SetProtoMethod(tmpl, "fd_renumber", WASI::FdRenumber);
  V(FdSeek, "fd_seek")
  env->SetProtoMethod(tmpl, "fd_sync", WASI::FdSync);
  env->SetProtoMethod(tmpl, "fd_tell", WASI::FdTell);
  env->SetProtoMethod(tmpl, "fd_write", WASI::FdWrite);
  env->SetProtoMethod(tmpl, "path_create_directory", WASI::PathCreateDirectory);
  env->SetProtoMethod(tmpl, "path_filestat_get", WASI::PathFilestatGet);
  env->SetProtoMethod(tmpl,
                      "path_filestat_set_times",
                      WASI::PathFilestatSetTimes);
  env->SetProtoMethod(tmpl, "path_link", WASI::PathLink);
  env->SetProtoMethod(tmpl, "path_open", WASI::PathOpen);
  env->SetProtoMethod(tmpl, "path_readlink", WASI::PathReadlink);
  env->SetProtoMethod(tmpl, "path_remove_directory", WASI::PathRemoveDirectory);
  env->SetProtoMethod(tmpl, "path_rename", WASI::PathRename);
  env->SetProtoMethod(tmpl, "path_symlink", WASI::PathSymlink);
  env->SetProtoMethod(tmpl, "path_unlink_file", WASI::PathUnlinkFile);
  env->SetProtoMethod(tmpl, "poll_oneoff", WASI::PollOneoff);
  env->SetProtoMethod(tmpl, "proc_exit", WASI::ProcExit);
  env->SetProtoMethod(tmpl, "proc_raise", WASI::ProcRaise);
  V(RandomGet, "random_get")
  V(SchedYield, "sched_yield")
  V(SockRecv, "sock_recv")
  V(SockSend, "sock_send")
  V(SockShutdown, "sock_shutdown")
#undef V

  env->SetInstanceMethod(tmpl, "_setMemory", WASI::_SetMemory);

  env->SetConstructorFunction(target, "WASI", tmpl);
}


}  // namespace wasi
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(wasi, node::wasi::Initialize)
