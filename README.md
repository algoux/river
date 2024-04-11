# river

## 用法

```bash
$ river -h
example: `river -vvv -- /usr/bin/echo hello world`

Usage: river.exe [OPTIONS] -- <COMMAND>...

Arguments:
  <COMMAND>...  Program to run and command line arguments

Options:
  -i, --input <INPUT>
          Input stream. The default value is STDIN(0)
  -o, --output <OUTPUT>
          Output stream. The default value is STDOUT(1)
  -e, --error <ERROR>
          Error stream. The default value is STDERR(2)
  -r, --result <RESULT>
          Output location of the running result. The default value is STDOUT(1)
  -t, --time-limit <TIME_LIMIT>
          Time limit, in ms. The default value is unlimited
  -c, --cpu-time-limit <CPU_TIME_LIMIT>
          CPU Time limit, in ms. The default value is unlimited
  -m, --memory-limit <MEMORY_LIMIT>
          Memory limit, in kib. The default value is unlimited
  -v, --verbose...
          Increase logging verbosity
  -q, --quiet...
          Decrease logging verbosity
  -h, --help
          Print help
  -V, --version
          Print version
```

**在 linux 环境下，需要额外安装 `runit`：**

```shell
$ gcc resources/runit.s -o /usr/bin/runit
```

## 结果

结果的格式为 JSON

| 字段              | 含义                 |
|-----------------|--------------------|
| `time_used`     | 程序运行用时             |
| `cpu_time_used` | 程序运行使用 CPU 时间      |
| `memory_used`   | 程序运行使用内存           |
| `exit_code`     | 程序退出 code，正常情况下为 0 |
| `status`        | 正常情况下为 0           |
| `signal`        | 正常情况下为 0           |

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
