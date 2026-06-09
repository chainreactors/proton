# Proton FFI

Proton FFI 将 proton 引擎的核心扫描能力导出为标准 C ABI，生成 `.so` / `.dylib` / `.dll` 动态库或 `.a` 静态库，使任何支持 C FFI 的语言（Rust、Python、C/C++、Java/JNI、C#/P-Invoke、Node.js 等）都能直接调用 proton 的文件敏感信息扫描能力。

## 能力概览

| 能力 | 说明 |
|------|------|
| 内置模板扫描 | 自带编译好的 keys / spray 规则库，无需额外文件即可检测 AWS 密钥、私钥、Token、凭据泄露等 |
| 自定义模板 | 加载任意 YAML 模板文件或目录，支持自定义正则/关键词规则 |
| 目录扫描 | 递归扫描目录，自动跳过二进制文件和无关目录，支持归档文件（zip/tar/gz）内扫描 |
| 内存数据扫描 | 直接扫描内存中的原始字节，适用于网络流量、HTTP 响应体等非文件场景 |
| 多实例 | 基于 handle 管理，可同时创建多个 Scanner 实例，线程安全 |
| JSON 输出 | 所有扫描结果以 JSON 字符串返回，跨语言解析无障碍 |

## 构建

**前置条件**: Go 1.24+, GCC (CGO 需要 C 编译器)

```bash
# 动态库 (.so / .dylib / .dll + .h)
make libproton

# 静态库 (.a + .h)
make libproton-static
```

或手动执行：

```bash
# 动态库
CGO_ENABLED=1 go build -buildmode=c-shared -o libproton.so ./cmd/export/

# 静态库
CGO_ENABLED=1 go build -buildmode=c-archive -o libproton.a ./cmd/export/
```

构建完成后会生成两个文件：

- `libproton.so` 或 `libproton.a` — 库文件
- `libproton.h` — C 头文件，包含所有导出函数签名

## API 参考

### ProtonVersion

```c
char* ProtonVersion();
```

返回版本号字符串（如 `"v0.1.1"`）。调用方需通过 `ProtonFreeString` 释放。

### ProtonNewScanner

```c
int ProtonNewScanner(const char* category);
```

使用内置模板创建 Scanner。

**参数**:
- `category` — 模板分类，支持 `"keys"`（密钥检测，默认）、`"spray"`、`"all"`。传 `NULL` 等同于 `"keys"`。

**返回值**: Scanner handle（> 0），失败返回 0。

### ProtonNewScannerFromPath

```c
int ProtonNewScannerFromPath(const char* path);
```

从自定义 YAML 模板文件或目录创建 Scanner。传入目录时会递归加载所有 `.yaml` / `.yml` 文件。

**参数**:
- `path` — 模板文件或目录路径。

**返回值**: Scanner handle（> 0），失败返回 0。

### ProtonScanDir

```c
char* ProtonScanDir(int handle, const char* target);
```

递归扫描目标目录，返回所有发现的 JSON 数组字符串。内部使用多线程并行扫描。

**参数**:
- `handle` — `ProtonNewScanner` 或 `ProtonNewScannerFromPath` 返回的 handle。
- `target` — 要扫描的目录路径。

**返回值**: JSON 字符串（`Finding` 数组），无发现时返回 `"[]"`。调用方需通过 `ProtonFreeString` 释放。

### ProtonScanData

```c
char* ProtonScanData(int handle, const void* data, int dataLen, const char* filePath);
```

扫描内存中的原始字节数据。适用于非文件场景（如网络流量、API 响应体、数据库内容等）。

**参数**:
- `handle` — Scanner handle。
- `data` — 数据指针。
- `dataLen` — 数据长度（字节）。
- `filePath` — 虚拟文件路径，用于结果中的路径标识，可传 `NULL`。

**返回值**: JSON 字符串（`Finding` 数组）。调用方需通过 `ProtonFreeString` 释放。

### ProtonFreeScanner

```c
void ProtonFreeScanner(int handle);
```

释放 Scanner 实例。释放后该 handle 不可再使用。

### ProtonFreeString

```c
void ProtonFreeString(char* s);
```

释放由 `ProtonVersion`、`ProtonScanDir`、`ProtonScanData` 返回的字符串。**每个返回的字符串都必须调用此函数释放，否则会内存泄漏。**

## Finding JSON 结构

```json
{
  "template-id": "aws-access-key",
  "template-name": "Amazon Web Services Access Key ID - Detect",
  "severity": "info",
  "file": "/path/to/target/.env",
  "matches": {
    "matcher-name": [
      {"value": "AKIAIOSFODNN7EXAMPLE", "line": 2, "offset": 0}
    ]
  },
  "extracts": [
    {"value": "AKIAIOSFODNN7EXAMPLE", "line": 2, "offset": 0}
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `template-id` | string | 命中的规则 ID |
| `template-name` | string | 规则名称 |
| `severity` | string | 严重程度：`critical` / `high` / `medium` / `low` / `info` |
| `file` | string | 文件路径 |
| `matches` | object | 匹配器命中，key 为 matcher 名称，value 为命中事件数组 |
| `extracts` | array | 提取器命中事件数组 |

每个事件包含 `value`（匹配内容）、`line`（行号）、`offset`（字节偏移）。

## 典型使用流程

```
ProtonNewScanner("keys")  →  handle
        │
        ├── ProtonScanDir(handle, "/target")     →  JSON  →  ProtonFreeString
        ├── ProtonScanData(handle, buf, len, "")  →  JSON  →  ProtonFreeString
        └── ...（可重复调用）
        │
ProtonFreeScanner(handle)
```

一个 Scanner 创建后可反复用于扫描不同目标，最后统一释放。

## 集成示例

### Python (ctypes)

```python
import ctypes
import json

lib = ctypes.CDLL("./libproton.so")

lib.ProtonVersion.restype = ctypes.c_char_p
lib.ProtonNewScanner.argtypes = [ctypes.c_char_p]
lib.ProtonNewScanner.restype = ctypes.c_int
lib.ProtonScanDir.argtypes = [ctypes.c_int, ctypes.c_char_p]
lib.ProtonScanDir.restype = ctypes.c_char_p
lib.ProtonScanData.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
lib.ProtonScanData.restype = ctypes.c_char_p
lib.ProtonFreeScanner.argtypes = [ctypes.c_int]
lib.ProtonFreeString.argtypes = [ctypes.c_char_p]

# 创建 scanner
handle = lib.ProtonNewScanner(b"keys")

# 扫描目录
result = lib.ProtonScanDir(handle, b"/path/to/scan")
findings = json.loads(result.decode())
for f in findings:
    print(f"[{f['severity']}] {f['template-id']} {f['file']}")

# 扫描内存数据
data = b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
result = lib.ProtonScanData(handle, data, len(data), b"memory.txt")
findings = json.loads(result.decode())

# 释放
lib.ProtonFreeScanner(handle)
```

### C

```c
#include <stdio.h>
#include "libproton.h"

int main() {
    char* ver = ProtonVersion();
    printf("proton %s\n", ver);
    ProtonFreeString(ver);

    int handle = ProtonNewScanner("keys");
    if (handle == 0) {
        fprintf(stderr, "failed to create scanner\n");
        return 1;
    }

    char* result = ProtonScanDir(handle, "/path/to/scan");
    printf("%s\n", result);
    ProtonFreeString(result);

    // 扫描内存数据
    const char* content = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    char* data_result = ProtonScanData(handle, (void*)content, strlen(content), "test.txt");
    printf("%s\n", data_result);
    ProtonFreeString(data_result);

    ProtonFreeScanner(handle);
    return 0;
}
```

编译（动态链接）：

```bash
gcc -o demo demo.c -L. -lproton -lpthread
LD_LIBRARY_PATH=. ./demo
```

编译（静态链接）：

```bash
gcc -o demo demo.c libproton.a -lpthread -lm
./demo
```

### Rust

完整示例见 [`examples/rust-demo/`](../examples/rust-demo/)。

**项目结构**:

```
examples/rust-demo/
├── Cargo.toml
├── build.rs        # 链接配置
├── libproton.a     # 静态库（需先 make libproton-static 构建）
├── libproton.h
└── src/
    └── main.rs
```

**build.rs** — 告诉 cargo 链接静态库：

```rust
fn main() {
    let dir = std::env::current_dir().unwrap();
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static=proton");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=m");
}
```

**FFI 声明**:

```rust
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

extern "C" {
    fn ProtonVersion() -> *mut c_char;
    fn ProtonNewScanner(category: *const c_char) -> c_int;
    fn ProtonNewScannerFromPath(path: *const c_char) -> c_int;
    fn ProtonScanDir(handle: c_int, target: *const c_char) -> *mut c_char;
    fn ProtonScanData(handle: c_int, data: *const c_void, data_len: c_int, file_path: *const c_char) -> *mut c_char;
    fn ProtonFreeScanner(handle: c_int);
    fn ProtonFreeString(s: *mut c_char);
}
```

**安全封装**:

```rust
fn proton_scan_dir(handle: c_int, target: &str) -> Vec<Finding> {
    let c_target = CString::new(target).unwrap();
    unsafe {
        let ptr = ProtonScanDir(handle, c_target.as_ptr());
        let json = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        ProtonFreeString(ptr);
        serde_json::from_str(&json).unwrap_or_default()
    }
}
```

**运行**:

```bash
# 1. 构建静态库
make libproton-static

# 2. 复制到 demo 目录
cp libproton.a libproton.h examples/rust-demo/

# 3. 构建并运行
cd examples/rust-demo
cargo build
cargo run -- scan /path/to/scan
cargo run -- scan-data /path/to/file
cargo run -- scan /path/to/scan spray    # 使用 spray 分类
```

## 跨平台说明

| 平台 | 动态库 | 静态库 | 备注 |
|------|--------|--------|------|
| Linux x86_64 | `libproton.so` | `libproton.a` | 需要 `gcc` 和 `pthread` |
| macOS arm64/x86_64 | `libproton.dylib` | `libproton.a` | 需要 Xcode Command Line Tools |
| Windows x86_64 | `libproton.dll` | `libproton.a` | 需要 MinGW 或 MSVC 环境 |

交叉编译示例（Linux 上编译 macOS 库）：

```bash
GOOS=darwin GOARCH=arm64 CC=aarch64-apple-darwin-gcc \
  CGO_ENABLED=1 go build -buildmode=c-shared -o libproton.dylib ./cmd/export/
```

## 注意事项

1. **内存管理**: 所有返回 `char*` 的函数都通过 C 的 `malloc` 分配内存，**必须调用 `ProtonFreeString` 释放**，不能用目标语言自身的 free/dealloc。
2. **线程安全**: Scanner 创建/销毁和扫描操作均线程安全，多个 goroutine/线程可共享同一 handle 并发扫描。
3. **Go Runtime**: 静态链接时 Go runtime 会一起打入二进制，不需要目标机器安装 Go。动态链接时 `.so` / `.dylib` 自包含 Go runtime。
4. **handle 生命周期**: handle 在 `ProtonFreeScanner` 后失效。对已释放 handle 调用 Scan 会返回空结果 `"[]"`，不会 crash。
