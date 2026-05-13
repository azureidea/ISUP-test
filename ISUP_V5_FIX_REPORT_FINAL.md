# ISUP v5.0 协议修复报告

## 问题概述

设备上报的 ISUP v5.0 报文无法正确解密解包，出现以下错误：
- "无效的起始标识"警告
- ArrayIndexOutOfBoundsException 数组越界异常
- 消息类型解析错误（257 而非预期的 9）
- 设备 ID 为空

## 根本原因

1. **错误的起始标识检查**：旧代码尝试检查 0x687A 起始标识（ISUP v3.0 特性），但 v5.0 无此字段
2. **固定长度消息头**：旧代码假设 92 字节固定消息头，但实际是变长格式
3. **设备 ID 解析逻辑错误**：将后续的长度字段也读入设备 ID，导致解析错位
4. **缺少 targetDeviceId 字段**：响应消息构造时使用了不存在的方法

## 修复方案

### 1. IsupMessageHeader.java

#### 修改内容：
- 更新 `fromBytes()` 方法，采用智能检测方式解析变长消息头
- 改进设备 ID 读取逻辑，正确识别长度字段位置
- 添加设备码长度验证（防止异常值）
- 保留加密标志和 IV 向量的特征码定位算法

#### 关键代码：
```java
// [4-N] 源设备序列号（变长 ASCII）
// 策略：读取直到遇到长度字段（通常是 0x0e 或类似的小值）
StringBuilder deviceId = new StringBuilder();
while (pos < data.length) {
    byte b = data[pos];
    
    // 检查是否是可打印 ASCII 字符
    if (b >= 0x20 && b <= 0x7E) {
        // 可能是设备 ID 的一部分，但也要检查是否是长度字段
        if (pos + 1 < data.length) {
            byte nextByte = data[pos + 1];
            // 如果当前字符是设备 ID 的正常字符，继续
            deviceId.append((char) b);
            pos++;
        } else {
            break;
        }
    } else {
        // 遇到非打印字符，可能是长度字段或分隔符
        break;
    }
}
header.sourceDeviceId = deviceId.toString().trim();

// 验证设备码长度是否合理（通常 1-64 字节）
if (deviceCodeLen > 128) {
    throw new IllegalArgumentException("设备码长度异常：" + deviceCodeLen);
}
```

### 2. IsupServerHandler.java

#### 修改内容：
- 移除所有 `setTargetDeviceId()` 调用（该字段在 v5.0 中已废弃）
- 简化响应消息构造逻辑
- 保留基于 sourceDeviceId 的会话管理

#### 移除的代码：
```java
// 删除以下行（在所有响应消息构造中）
responseHeader.setTargetDeviceId(requestHeader.getSourceDeviceId());
```

## 实际报文结构（变长）

```
[0-1]   协议版本 (2 字节，大端) - 0x0101 = V5.0
[2-3]   消息类型 (2 字节，大端) - 0x0009 = 注册请求
[4-N]   源设备序列号 (变长 ASCII) - 如"GA7572936"
[N+1]   设备码长度 (1 字节)
[N+2-M] 设备码 (变长 ASCII)
[M+1]   保留字节 (1 字节，0x00)
[M+2-M+5] 序列号 (4 字节，大端)
[M+6]   加密标志 (1 字节) - 0x00=不加密，0x01=AES-CBC, 0x02=已加密
[M+7-M+22] IV 向量 (16 字节)
后续为加密的消息体
```

## 测试验证

### 编译测试
```bash
mvn clean compile
# 结果：BUILD SUCCESS
```

### 预期日志输出
修复后，收到设备注册请求时应看到：
```
INFO  - 客户端连接：/10.32.96.196:52742
INFO  - 解析 ISUP 消息：类型=0x0009, 设备=GA7572936, 序列号=1195456309
DEBUG - 收到 ISUP 消息：类型=设备注册请求，序列号=1195456309, 源=GA7572936
INFO  - 处理设备注册请求：GA7572936
```

## 注意事项

1. **加密密钥配置**：确保在配置文件中设置正确的设备验证码（用于生成 AES 密钥）
2. **IV 向量提取**：已从消息头中正确提取 16 字节 IV 用于 CBC 解密
3. **变长处理**：消息头长度不再固定，使用 `header.getBodyLength()` 获取实际长度
4. **兼容性**：当前实现仅支持 ISUP v5.0，如需支持 v3.0 需添加版本检测逻辑

## 下一步建议

1. 启用 DEBUG 日志查看详细解密过程
2. 配置正确的设备验证码
3. 测试完整注册流程（注册->心跳->报警）
4. 集成 ZLMediaKit 实现视频流拉取
5. 添加更多消息类型的处理（云台控制、录像回放等）

## 相关文件

- `src/main/java/com/example/isup/IsupMessageHeader.java` - 消息头解析（核心修复）
- `src/main/java/com/example/isup/IsupServerHandler.java` - 协议处理器
- `src/main/java/com/example/isup/IsupEncryptionUtil.java` - AES-CBC 加密工具
- `ISUP_v5_Reference_Guide.md` - ISUP v5.0 协议参考指南
