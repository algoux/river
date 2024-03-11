# river

## 系统支持

`~` 代表开发中的功能

| 特性          | Linux | Windows | macOS |
|-------------|-------|---------|-------|
| 执行指定命令      | ~     | √       | ~     |
| 流重定向        | ~     | √       | ~     |
| 运行时间统计      | ~     | √       | ~     |
| 运行 CPU 时间统计 | ~     | √       | ~     |
| 运行内存统计      | ~     | √       | ~     |
| 运行时间限制      | ~     | √       | ~     |
| 运行 CPU 时间限制 | ~     | ~       | ~     |
| 运行内存限制      | ~     | ~       | ~     |
| 获取进程退出状态    | ~     | ~       | ~     |
| 切换工作空间      | ~     | ~       | ~     |
| 传递环境变量      | ~     | ~       | ~     |
| 网络限制        | ~     | ~       | ~     |
| 写入文件大小限制    | ~     | ~       | ~     |
| 进程/线程数量限制   | ~     | ~       | ~     |
| 危险系统调用限制    | ~     | ~       | ~     |
| 执行用户权限限制    | ~     | ~       | ~     |
| 平滑退出        | ~     | ~       | ~     |

**注意：** Windows 平台下运行 CPU 时间限制与运行内存限制不能保证精确，请不要以此为基准进行判断。

## 测试

```bash
cargo test -- --test-threads=1
```

测试涉及文件操作，建议顺序执行测试用例（并发限制为 1）
