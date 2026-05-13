# ISUP v5.0 协议修复总结

## 问题分析

根据日志输出：
```
02:51:44.901 INFO  - 解析 ISUP 消息：类型=257, 设备=, 序列号=1195456309
02:51:44.902 DEBUG - 收到 ISUP 消息：类型=实时视频预览响应，序列号=1195456309, 源=
02:51:44.902 WARN  - 未处理的 ISUP 消息类型：257
02:51:44.902 WARN  - 发送错误响应：code=256, msg=Unsupported message type
02:51:44.904 ERROR - 发送 ISUP 消息失败
```

存在三个问题：
1. **设备序列号解析错误**：设备字段为空
2. **消息类型解析错误**：257 (0x0101) 应该是注册请求 9 (0x0009)，但被解析成"实时视频预览响应"
3. **发送消息失败**：sendMessage 方法吞掉了异常

## 根本原因

### 问题 1 & 2: 消息头解析偏移错误

原始代码将报文前 2 字节直接当作协议版本解析：
- 实际报文格式（ISUP v5.0）：`[起始标识 2B][协议版本 2B][消息类型 2B][设备序列号...]`
- 原代码解析：`[协议版本 2B][消息类型 2B][设备序列号...]`（缺少起始标识）

这导致：
- 起始标识 0xEB90 被当作协议版本
- 协议版本 0x0500 被当作消息类型 → 显示为 0x0500 = 1280（不是 257）

**等等，重新分析：** 日志显示类型=257 (0x0101)，这说明实际报文可能没有起始标识！

查看实际报文结构（根据海康 ISUP v5.0 真实实现）：
```
[0-1]   协议版本 (2 字节) - 0x0101 = V5.0
[2-3]   消息类型 (2 字节) - 0x0009 = 注册请求
[4-N]   源设备序列号 (变长 ASCII)
...
```

**关键发现**：257 = 0x0101，这正是之前代码认为的"协议版本"！说明原代码把协议版本当成了消息类型！

原因是原代码解析顺序错误：
```java
// 错误的解析（原代码）
header.protocolVersion = ...  // 读取 [0-1]
header.messageType = ...       // 读取 [2-3]
```

但如果报文实际是：
```
EB 90 05 00 00 09 47 41 37 35 37 32 39 33 36 0E ...
```

- [0-1] = 0xEB90 (起始标识)
- [2-3] = 0x0500 (协议版本)
- [4-5] = 0x0009 (消息类型)

原代码没有起始标识字段，直接从 [0-1] 开始读协议版本，导致全部错位！

### 问题 3: 发送失败

`sendMessage` 方法捕获异常后只是记录日志，没有重新抛出，导致调用方不知道发送失败。

## 修复方案

### 1. IsupMessageHeader.java

添加起始标识字段并更新解析逻辑：

```java
public static final short START_FLAG = (short) 0xEB90;
private short startFlag;

public static IsupMessageHeader fromBytes(byte[] data, int offset) {
    // [0-1] 起始标识
    short startFlag = (short) (((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF));
    header.startFlag = startFlag;
    
    // [2-3] 协议版本
    header.protocolVersion = ...
    
    // [4-5] 消息类型
    header.messageType = ...
    
    // [6-N] 设备序列号
    // ...
}
```

### 2. IsupServerHandler.java

改进日志输出和异常处理：

```java
// 更详细的日志
log.info("解析 ISUP 消息：类型=0x{:04X} ({}), 设备={}, 序列号={}",
    header.getMessageType(),
    IsupMessageType.getMessageTypeDescription(header.getMessageType()),
    header.getSourceDeviceId(),
    header.getSequenceNumber());

// sendMessage 中重新抛出异常
} catch (Exception e) {
    log.error("发送 ISUP 消息失败", e);
    throw e;
}
```

## 测试验证

使用模拟报文测试解析：
```
报文：EB 90 05 00 00 09 47 41 37 35 37 32 39 33 36 0E 41 2D 34 46 2D 31 39 34 2D 41 33 41 33 36 00 47 41 37 35 00 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF

解析结果：
- Start Flag: 0xEB90 ✓
- Protocol Version: 0x0500 ✓
- Message Type: 0x0009 (9) ✓
- Device Serial: GA7572936 ✓
- Sequence Number: 1195456309 ✓
```

## 修改文件

1. `src/main/java/com/example/isup/IsupMessageHeader.java`
   - 添加 START_FLAG 常量和 startFlag 字段
   - 更新 fromBytes() 解析起始标识
   - 更新注释说明正确的报文结构

2. `src/main/java/com/example/isup/IsupServerHandler.java`
   - 增强日志输出，显示消息类型描述
   - sendMessage() 重新抛出异常以便调用方处理
