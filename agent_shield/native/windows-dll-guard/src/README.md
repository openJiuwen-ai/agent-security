# 原生 Guard 源码

构建、第三方许可、Detours 版本、运行时接口和安全边界见 [上级说明](../README.md)。

- `guard.c`：文件/进程 Hook、IPC 和初始化；使用 Detours 事务安装。
- `network.c`：DNS、WinHTTP、socket 和代理目标处理。
- `socket_address_snapshot.c` 供网络 Hook 与原生测试客户端共用，保存调用时的目的地址。
- `child_injection.c`：子进程导入表注入。
- `child_pe.c` 校验 AMD64 映像头、描述符数量和路径缓冲区。原生测试客户端和 DLL 使用同一份 C 校验代码，与 SDK 根程序校验比较接受结果和 Win32 错误码。

原生协议 4；当前支持 Windows x64。
