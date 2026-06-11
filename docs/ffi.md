# Proton FFI

Proton FFI 将 proton 引擎的核心匹配能力导出为标准 C ABI，生成 `.so` / `.dylib` / `.dll` 动态库或 `.a` 静态库，使任何支持 C FFI 的语言（Rust、Python、C/C++、Java/JNI、C#/P-Invoke、Node.js 等）都能直接调用 proton 的匹配引擎。

## 能力概览

| 能力 | 说明 |
|------|------|
| 自定义模板 | 加载任意 YAML 模板文件或目录 |
| 文本数据扫描 | 按行匹配内存中的文本数据（配置、日志、HTTP 响应体等） |
| 二进制数据扫描 | 滑动窗口匹配二进制数据（进程内存、网络流量等） |
| 多实例 | 基于 handle 管理，线程安全 |
| JSON 输出 | 所有扫描结果以 JSON 字符串返回 |

## 构建

**前置条件**: Go 1.24+, GCC (CGO)

```bash
# 动态库 (.so / .dylib / .dll + .h)
make libproton

# 静态库 (.a + .h)
make libproton-static
```

## API 参考

### ProtonVersion

```c
char* ProtonVersion();
```

返回版本号字符串。调用方需通过 `ProtonFreeString` 释放。

### ProtonNewScanner

```c
int ProtonNewScanner(const char* path);
```

从 YAML 模板文件或目录创建 Scanner。传入目录时递归加载所有 `.yaml` / `.yml` 文件。

**返回值**: Scanner handle（> 0），失败返回 0。

### ProtonScanData

```c
char* ProtonScanData(int handle, const void* data, int dataLen, const char* filePath);
```

按行扫描文本数据。适用于配置文件、日志、API 响应体等文本场景。

**参数**:
- `handle` — Scanner handle
- `data` — 数据指针
- `dataLen` — 数据长度（字节）
- `filePath` — 虚拟路径标识，可传 `NULL`

**返回值**: JSON 字符串（`Finding` 数组）。需 `ProtonFreeString` 释放。

### ProtonScanBlock

```c
char* ProtonScanBlock(int handle, const void* data, int dataLen, const char* label);
```

滑动窗口扫描二进制数据。适用于进程内存、网络流量等非文本场景。

**参数**:
- `handle` — Scanner handle
- `data` — 数据指针
- `dataLen` — 数据长度（字节）
- `label` — 数据来源标签（如 `"pid:1234:heap"`），可传 `NULL`

**返回值**: JSON 字符串（`Finding` 数组）。需 `ProtonFreeString` 释放。

### ProtonFreeScanner

```c
void ProtonFreeScanner(int handle);
```

释放 Scanner 实例。

### ProtonFreeString

```c
void ProtonFreeString(char* s);
```

释放返回的字符串。**每个返回的 `char*` 都必须调用此函数释放。**

## Finding JSON 结构

```json
{
  "template-id": "aws-access-key",
  "template-name": "Amazon Web Services Access Key ID - Detect",
  "severity": "info",
  "file": "config.env",
  "matches": {
    "matcher-name": [{"value": "AKIAIOSFODNN7EXAMPLE", "line": 2, "offset": 0}]
  },
  "extracts": [{"value": "AKIAIOSFODNN7EXAMPLE", "line": 2, "offset": 0}]
}
```

## 使用流程

```
ProtonNewScanner("/path/to/templates")  →  handle
        │
        ├── ProtonScanData(handle, buf, len, "config.env")  →  JSON  →  ProtonFreeString
        ├── ProtonScanBlock(handle, mem, size, "pid:1234")  →  JSON  →  ProtonFreeString
        └── ...（可重复调用）
        │
ProtonFreeScanner(handle)
```

## 集成示例

### Python

```python
import ctypes, json

lib = ctypes.CDLL("./libproton.so")
lib.ProtonNewScanner.argtypes = [ctypes.c_char_p]
lib.ProtonNewScanner.restype = ctypes.c_int
lib.ProtonScanData.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
lib.ProtonScanData.restype = ctypes.c_char_p
lib.ProtonScanBlock.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
lib.ProtonScanBlock.restype = ctypes.c_char_p
lib.ProtonFreeScanner.argtypes = [ctypes.c_int]
lib.ProtonFreeString.argtypes = [ctypes.c_char_p]

handle = lib.ProtonNewScanner(b"/path/to/templates")

# 文本扫描
data = b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
result = lib.ProtonScanData(handle, data, len(data), b"env.txt")
print(json.loads(result.decode()))

# 二进制扫描
binary = read_process_memory(pid=1234)
result = lib.ProtonScanBlock(handle, binary, len(binary), b"pid:1234:heap")
print(json.loads(result.decode()))

lib.ProtonFreeScanner(handle)
```

### C

```c
#include <stdio.h>
#include <string.h>
#include "libproton.h"

int main() {
    int handle = ProtonNewScanner("/path/to/templates");
    const char* content = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    char* result = ProtonScanData(handle, (void*)content, strlen(content), "test.txt");
    printf("%s\n", result);
    ProtonFreeString(result);
    ProtonFreeScanner(handle);
    return 0;
}
```

### Rust FFI 声明

```rust
extern "C" {
    fn ProtonVersion() -> *mut c_char;
    fn ProtonNewScanner(path: *const c_char) -> c_int;
    fn ProtonScanData(handle: c_int, data: *const c_void, len: c_int, path: *const c_char) -> *mut c_char;
    fn ProtonScanBlock(handle: c_int, data: *const c_void, len: c_int, label: *const c_char) -> *mut c_char;
    fn ProtonFreeScanner(handle: c_int);
    fn ProtonFreeString(s: *mut c_char);
}
```

## 注意事项

1. **内存管理**: 所有返回 `char*` 必须调用 `ProtonFreeString` 释放
2. **线程安全**: Scanner 创建/销毁和扫描操作均线程安全
3. **Go Runtime**: 静态链接时 Go runtime 打入二进制，不需要目标机安装 Go
4. **handle 生命周期**: `ProtonFreeScanner` 后 handle 失效，对已释放 handle 扫描返回 `"[]"`
