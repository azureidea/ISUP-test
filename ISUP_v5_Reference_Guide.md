# 海康威视 ISUP v5.0 协议参考实现指南

> **声明**：本文档是基于公开资料和逆向工程整理的参考实现指南，非海康威视官方文档。实际开发请以海康威视官方提供的《ISUP协议开发文档》为准。

---

## 目录

1. [协议概述](#1-协议概述)
2. [消息结构定义](#2-消息结构定义)
3. [加密解密机制](#3-加密解密机制)
4. [通信流程](#4-通信流程)
5. [关键代码实现](#5-关键代码实现)
6. [常见问题排查](#6-常见问题排查)
7. [附录](#7-附录)

---

## 1. 协议概述

### 1.1 协议简介

ISUP (Intelligent Surveillance Unified Platform) 是海康威视推出的智能安防统一平台接入协议，v5.0 版本支持：

- 设备注册与认证
- 实时视频流传输
- 报警事件上报
- 设备状态监控
- 双向语音对讲
- 云台控制

### 1.2 通信模式

- **传输层**：TCP长连接
- **默认端口**：7660 (可配置)
- **字符编码**：UTF-8
- **字节序**：大端模式 (Big-Endian)

### 1.3 安全机制

- **认证方式**：基于设备序列号和密钥的双向认证
- **加密算法**：AES-128-CBC
- **密钥协商**：注册阶段动态协商会话密钥

---

## 2. 消息结构定义

### 2.1 消息头格式 (Message Header)

所有ISUP消息都包含固定长度的消息头，总长度：**64字节**

| 偏移量 | 字段名 | 长度(字节) | 类型 | 说明 |
|--------|--------|-----------|------|------|
| 0 | magicNumber | 4 | uint32 | 魔数，固定为 `0x53555049` ("ISUP") |
| 4 | version | 2 | uint16 | 协议版本，v5.0为 `0x0500` |
| 6 | reserved | 2 | uint16 | 保留字段，填0 |
| 8 | totalLength | 4 | uint32 | 整个消息长度(含头部) |
| 12 | commandType | 4 | uint32 | 命令类型 |
| 16 | sequenceNo | 4 | uint32 | 序列号，用于请求响应匹配 |
| 20 | errorCode | 4 | uint32 | 错误码(响应消息使用) |
| 24 | deviceId | 48 | byte[48] | **设备序列号**(ASCII编码，不足补0) |
| 72 | encryptFlag | 1 | uint8 | 加密标志：0-不加密，1-加密 |
| 73 | compressFlag | 1 | uint8 | 压缩标志：0-不压缩，1-压缩 |
| 74 | reserved2 | 2 | uint16 | 保留字段，填0 |
| 76 | iv | 16 | byte[16] | **CBC模式IV向量**(仅加密消息有效) |
| 92 | reserved3 | 20 | byte[20] | 保留字段，填0 |

**注意**：早期文档可能将deviceId描述为8字节，但v5.0实际使用48字节存储完整设备序列号。

### 2.2 消息体格式 (Message Body)

消息体紧跟在消息头之后，长度 = `totalLength - 92` (消息头实际占用92字节，部分实现为112字节带对齐)

- 如果 `encryptFlag = 1`，消息体为AES加密后的密文
- 如果 `compressFlag = 1`，解密后还需进行解压缩(Zlib)

### 2.3 常用命令类型

| 命令类型 | 十六进制 | 说明 |
|----------|---------|------|
| CMD_REGISTER_REQ | 0x00000101 | 设备注册请求 |
| CMD_REGISTER_RESP | 0x00000102 | 设备注册响应 |
| CMD_KEEPALIVE_REQ | 0x00000201 | 心跳请求 |
| CMD_KEEPALIVE_RESP | 0x00000202 | 心跳响应 |
| CMD_ALARM_UPLOAD | 0x00000301 | 报警上报 |
| CMD_STATUS_REPORT | 0x00000302 | 状态报告 |
| CMD_VIDEO_STREAM_REQ | 0x00000401 | 视频流请求 |
| CMD_VIDEO_STREAM_RESP | 0x00000402 | 视频流响应 |
| CMD_CONTROL_REQ | 0x00000501 | 控制请求 |
| CMD_CONTROL_RESP | 0x00000502 | 控制响应 |

---

## 3. 加密解密机制

### 3.1 加密算法规格

- **算法**：AES-128-CBC
- **密钥长度**：16字节 (128位)
- **工作模式**：CBC (Cipher Block Chaining)
- **填充方式**：PKCS5Padding / PKCS7Padding
- **IV向量**：16字节，每次加密随机生成，随消息头传输

### 3.2 密钥派生流程

#### 3.2.1 初始密钥

设备出厂时预设一个**设备密钥**(DeviceKey)，通常：
- 长度为16字节
- 可能是设备序列号的哈希值
- 或由平台统一分配

#### 3.2.2 会话密钥协商

```
┌─────────────┐                    ┌─────────────┐
│   Device    │                    │   Platform  │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  1. RegisterReq (加密: DeviceKey)│
       │─────────────────────────────────>│
       │                                  │
       │  2. RegisterResp (加密: DeviceKey)│
       │  { sessionKey, validPeriod }     │
       │<─────────────────────────────────│
       │                                  │
       │  3. 后续通信使用 sessionKey      │
       │══════════════════════════════════│
```

**会话密钥生成规则**：
- 平台在注册响应中下发新的会话密钥
- 会话密钥有效期通常为24小时
- 过期后需要重新注册或刷新密钥

### 3.3 加密流程

```java
/**
 * ISUP v5.0 AES-CBC 加密实现
 */
public byte[] encrypt(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
    // 1. 参数校验
    if (key == null || key.length != 16) {
        throw new IllegalArgumentException("Key must be 16 bytes");
    }
    if (iv == null || iv.length != 16) {
        throw new IllegalArgumentException("IV must be 16 bytes");
    }
    
    // 2. 初始化Cipher
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    
    // 3. 执行加密
    return cipher.doFinal(plaintext);
}
```

### 3.4 解密流程

```java
/**
 * ISUP v5.0 AES-CBC 解密实现
 */
public byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv) throws Exception {
    // 1. 参数校验
    if (key == null || key.length != 16) {
        throw new IllegalArgumentException("Key must be 16 bytes");
    }
    if (iv == null || iv.length != 16) {
        throw new IllegalArgumentException("IV must be 16 bytes");
    }
    
    // 2. 初始化Cipher
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    
    // 3. 执行解密
    return cipher.doFinal(ciphertext);
}
```

### 3.5 IV向量处理

**重要**：每条加密消息都必须使用**随机生成的IV**，并在消息头的IV字段中携带。

```java
/**
 * 生成随机IV
 */
public byte[] generateIV() {
    byte[] iv = new byte[16];
    SecureRandom random = new SecureRandom();
    random.nextBytes(iv);
    return iv;
}
```

---

## 4. 通信流程

### 4.1 完整注册流程

```
┌─────────────┐                              ┌─────────────┐
│   Device    │                              │   Platform  │
└──────┬──────┘                              └──────┬──────┘
       │                                            │
       │  TCP Connect                               │
       │───────────────────────────────────────────>│
       │                                            │
       │  RegisterReq                               │
       │  Header:                                   │
       │    - magicNumber: 0x53555049              │
       │    - version: 0x0500                       │
       │    - totalLength: 200                      │
       │    - commandType: 0x0101                   │
       │    - sequenceNo: 1                         │
       │    - deviceId: "ABC123456789..." (48字节)  │
       │    - encryptFlag: 1                        │
       │    - iv: [random 16 bytes]                 │
       │  Body: {                                   │
       │    deviceModel, firmwareVersion,           │
       │    timestamp, nonce                        │
       │  } (AES加密)                               │
       │───────────────────────────────────────────>│
       │                                            │
       │  [平台验证设备合法性]                       │
       │                                            │
       │  RegisterResp                              │
       │  Header:                                   │
       │    - commandType: 0x0102                   │
       │    - sequenceNo: 1                         │
       │    - errorCode: 0                          │
       │    - encryptFlag: 1                        │
       │    - iv: [random 16 bytes]                 │
       │  Body: {                                   │
       │    result: SUCCESS,                        │
       │    sessionKey: [16字节],                   │
       │    validPeriod: 86400,                     │
       │    serverTime: timestamp                   │
       │  } (AES加密)                               │
       │<───────────────────────────────────────────│
       │                                            │
       │  [设备保存sessionKey]                       │
       │                                            │
       │  KeepaliveReq (每30秒)                     │
       │  (使用sessionKey加密)                       │
       │───────────────────────────────────────────>│
       │                                            │
       │  KeepaliveResp                             │
       │<───────────────────────────────────────────│
       │                                            │
       │  ══════ 注册完成，开始业务通信 ══════       │
       │                                            │
```

### 4.2 报警上报流程

```
┌─────────────┐                              ┌─────────────┐
│   Device    │                              │   Platform  │
└──────┬──────┘                              └──────┬──────┘
       │                                            │
       │  AlarmUpload                               │
       │  Header:                                   │
       │    - commandType: 0x0301                   │
       │    - deviceId: 48字节序列号                │
       │    - encryptFlag: 1                        │
       │    - iv: [random]                          │
       │  Body: {                                   │
       │    alarmType: MOTION_DETECTION,            │
       │    alarmLevel: HIGH,                       │
       │    triggerTime: timestamp,                 │
       │    channelNo: 1,                           │
       │    snapshotUrl: "http://...",              │
       │    extendedInfo: {...}                     │
       │  } (AES加密)                               │
       │───────────────────────────────────────────>│
       │                                            │
       │  [平台处理报警]                             │
       │                                            │
       │  (可选) ControlReq                         │
       │  (联动动作：开启录像、声光报警等)            │
       │<───────────────────────────────────────────│
       │                                            │
       │  ControlResp                               │
       │───────────────────────────────────────────>│
       │                                            │
```

### 4.3 心跳保活机制

- **心跳间隔**：建议30秒
- **超时判定**：连续3次未收到心跳响应视为离线
- **重连策略**：指数退避 (1s, 2s, 4s, 8s, 16s, 30s...)

---

## 5. 关键代码实现

### 5.1 消息头结构定义 (Java)

```java
public class ISUPMessageHeader {
    private static final int HEADER_SIZE = 92;
    private static final int DEVICE_ID_LENGTH = 48;
    private static final int IV_LENGTH = 16;
    
    // 字段定义
    private long magicNumber;      // 4 bytes
    private int version;           // 2 bytes
    private int reserved;          // 2 bytes
    private long totalLength;      // 4 bytes
    private long commandType;      // 4 bytes
    private long sequenceNo;       // 4 bytes
    private long errorCode;        // 4 bytes
    private byte[] deviceId;       // 48 bytes
    private int encryptFlag;       // 1 byte
    private int compressFlag;      // 1 byte
    private int reserved2;         // 2 bytes
    private byte[] iv;             // 16 bytes
    private byte[] reserved3;      // 20 bytes
    
    // 序列化到字节数组
    public byte[] toBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_SIZE);
        buffer.order(ByteOrder.BIG_ENDIAN);
        
        buffer.putInt((int) magicNumber);
        buffer.putShort((short) version);
        buffer.putShort((short) reserved);
        buffer.putInt((int) totalLength);
        buffer.putInt((int) commandType);
        buffer.putInt((int) sequenceNo);
        buffer.putInt((int) errorCode);
        
        // 设备ID (48字节)
        byte[] paddedDeviceId = new byte[DEVICE_ID_LENGTH];
        if (deviceId != null) {
            System.arraycopy(deviceId, 0, paddedDeviceId, 0, 
                Math.min(deviceId.length, DEVICE_ID_LENGTH));
        }
        buffer.put(paddedDeviceId);
        
        buffer.put((byte) encryptFlag);
        buffer.put((byte) compressFlag);
        buffer.putShort((short) reserved2);
        
        // IV向量 (16字节)
        byte[] paddedIv = new byte[IV_LENGTH];
        if (iv != null) {
            System.arraycopy(iv, 0, paddedIv, 0, 
                Math.min(iv.length, IV_LENGTH));
        }
        buffer.put(paddedIv);
        
        buffer.put(reserved3);
        
        return buffer.array();
    }
    
    // 从字节数组反序列化
    public static ISUPMessageHeader fromBytes(byte[] data) {
        if (data.length < HEADER_SIZE) {
            throw new IllegalArgumentException("Data too short for header");
        }
        
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);
        
        ISUPMessageHeader header = new ISUPMessageHeader();
        header.magicNumber = Integer.toUnsignedLong(buffer.getInt());
        header.version = Short.toUnsignedInt(buffer.getShort());
        header.reserved = Short.toUnsignedInt(buffer.getShort());
        header.totalLength = Integer.toUnsignedLong(buffer.getInt());
        header.commandType = Integer.toUnsignedLong(buffer.getInt());
        header.sequenceNo = Integer.toUnsignedLong(buffer.getInt());
        header.errorCode = Integer.toUnsignedLong(buffer.getInt());
        
        header.deviceId = new byte[DEVICE_ID_LENGTH];
        buffer.get(header.deviceId);
        
        header.encryptFlag = Byte.toUnsignedInt(buffer.get());
        header.compressFlag = Byte.toUnsignedInt(buffer.get());
        header.reserved2 = Short.toUnsignedInt(buffer.getShort());
        
        header.iv = new byte[IV_LENGTH];
        buffer.get(header.iv);
        
        header.reserved3 = new byte[20];
        buffer.get(header.reserved3);
        
        return header;
    }
    
    // Getter/Setter省略...
}
```

### 5.2 加解密工具类

```java
public class ISUPCryptoUtil {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 16;
    private static final int IV_SIZE = 16;
    
    /**
     * 加密消息体
     */
    public static EncryptedData encrypt(byte[] plaintext, byte[] key) throws Exception {
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length");
        }
        
        // 生成随机IV
        byte[] iv = generateIV();
        
        // 执行加密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        return new EncryptedData(ciphertext, iv);
    }
    
    /**
     * 解密消息体
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv) throws Exception {
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length");
        }
        if (iv == null || iv.length != IV_SIZE) {
            throw new IllegalArgumentException("Invalid IV length");
        }
        
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        
        return cipher.doFinal(ciphertext);
    }
    
    /**
     * 生成随机IV
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
    
    /**
     * 封装加密结果
     */
    public static class EncryptedData {
        private final byte[] ciphertext;
        private final byte[] iv;
        
        public EncryptedData(byte[] ciphertext, byte[] iv) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }
        
        public byte[] getCiphertext() { return ciphertext; }
        public byte[] getIV() { return iv; }
    }
}
```

### 5.3 消息处理器

```java
public class ISUPMessageHandler {
    private static final long MAGIC_NUMBER = 0x53555049L; // "ISUP"
    private static final int VERSION_5_0 = 0x0500;
    
    private final Map<String, SessionContext> sessionMap = new ConcurrentHashMap<>();
    private final byte[] defaultDeviceKey; // 预设的设备密钥
    
    public ISUPMessageHandler(byte[] defaultDeviceKey) {
        this.defaultDeviceKey = defaultDeviceKey;
    }
    
    /**
     * 处理接收到的原始报文
     */
    public void handleRawMessage(byte[] rawData, Channel channel) {
        try {
            // 1. 解析消息头
            ISUPMessageHeader header = ISUPMessageHeader.fromBytes(rawData);
            
            // 2. 验证魔数和版本
            if (header.getMagicNumber() != MAGIC_NUMBER) {
                log.error("Invalid magic number: {}", header.getMagicNumber());
                return;
            }
            if (header.getVersion() != VERSION_5_0) {
                log.warn("Unsupported version: {}", header.getVersion());
            }
            
            // 3. 提取设备ID
            String deviceId = extractDeviceId(header.getDeviceId());
            
            // 4. 获取会话上下文
            SessionContext context = sessionMap.computeIfAbsent(deviceId, 
                id -> new SessionContext(id, defaultDeviceKey));
            
            // 5. 解密消息体 (如果需要)
            byte[] bodyData = Arrays.copyOfRange(rawData, 92, rawData.length);
            byte[] decryptedBody;
            
            if (header.getEncryptFlag() == 1) {
                decryptedBody = ISUPCryptoUtil.decrypt(
                    bodyData, 
                    context.getCurrentKey(), 
                    header.getIv()
                );
            } else {
                decryptedBody = bodyData;
            }
            
            // 6. 解压消息体 (如果需要)
            byte[] finalBody = header.getCompressFlag() == 1 
                ? decompress(decryptedBody) 
                : decryptedBody;
            
            // 7. 根据命令类型分发处理
            dispatchCommand(header, finalBody, context, channel);
            
        } catch (Exception e) {
            log.error("Failed to process message", e);
            // 发送错误响应
            sendErrorResponse(channel, e.getMessage());
        }
    }
    
    /**
     * 从48字节数组中提取设备ID字符串
     */
    private String extractDeviceId(byte[] deviceIdBytes) {
        // 去除末尾的0填充
        int len = deviceIdBytes.length;
        while (len > 0 && deviceIdBytes[len - 1] == 0) {
            len--;
        }
        return new String(deviceIdBytes, 0, len, StandardCharsets.UTF_8);
    }
    
    /**
     * 分发消息到具体处理器
     */
    private void dispatchCommand(ISUPMessageHeader header, byte[] body, 
                                 SessionContext context, Channel channel) {
        long cmdType = header.getCommandType();
        
        switch ((int) cmdType) {
            case 0x0101: // CMD_REGISTER_REQ
                handleRegisterRequest(header, body, context, channel);
                break;
            case 0x0201: // CMD_KEEPALIVE_REQ
                handleKeepaliveRequest(header, body, context, channel);
                break;
            case 0x0301: // CMD_ALARM_UPLOAD
                handleAlarmUpload(header, body, context, channel);
                break;
            default:
                log.warn("Unknown command type: {}", cmdType);
        }
    }
    
    /**
     * 处理注册请求
     */
    private void handleRegisterRequest(ISUPMessageHeader header, byte[] body,
                                       SessionContext context, Channel channel) {
        // 1. 解析注册请求体
        RegisterRequest req = parseRegisterRequest(body);
        
        // 2. 验证设备合法性
        boolean authenticated = authenticateDevice(context.getDeviceId(), req);
        
        if (!authenticated) {
            sendRegisterResponse(channel, header.getSequenceNo(), false, 
                "Authentication failed", null);
            return;
        }
        
        // 3. 生成会话密钥
        byte[] sessionKey = generateSessionKey();
        long validPeriod = 86400; // 24小时
        
        // 4. 更新会话上下文
        context.setCurrentKey(sessionKey);
        context.setSessionStartTime(System.currentTimeMillis());
        
        // 5. 构建注册响应
        RegisterResponse resp = new RegisterResponse();
        resp.setResult("SUCCESS");
        resp.setSessionKey(sessionKey);
        resp.setValidPeriod(validPeriod);
        resp.setServerTime(System.currentTimeMillis());
        
        // 6. 发送响应 (使用当前密钥加密)
        sendRegisterResponse(channel, header.getSequenceNo(), true, 
            "Success", resp, sessionKey);
        
        log.info("Device registered successfully: {}", context.getDeviceId());
    }
    
    // 其他处理方法省略...
}
```

### 5.4 会话上下文管理

```java
public class SessionContext {
    private final String deviceId;
    private volatile byte[] currentKey;
    private volatile long sessionStartTime;
    private volatile long lastHeartbeatTime;
    private final AtomicLong sequenceCounter = new AtomicLong(0);
    
    public SessionContext(String deviceId, byte[] initialKey) {
        this.deviceId = deviceId;
        this.currentKey = initialKey;
        this.lastHeartbeatTime = System.currentTimeMillis();
    }
    
    public synchronized void refreshSessionKey(byte[] newKey) {
        this.currentKey = newKey;
        this.sessionStartTime = System.currentTimeMillis();
    }
    
    public boolean isSessionExpired(long timeoutMs) {
        return System.currentTimeMillis() - sessionStartTime > timeoutMs;
    }
    
    public void updateHeartbeat() {
        this.lastHeartbeatTime = System.currentTimeMillis();
    }
    
    public boolean isHeartbeatTimeout(long timeoutMs) {
        return System.currentTimeMillis() - lastHeartbeatTime > timeoutMs;
    }
    
    public long getNextSequenceNo() {
        return sequenceCounter.incrementAndGet();
    }
    
    // Getter/Setter省略...
}
```

---

## 6. 常见问题排查

### 6.1 解密失败

**现象**：`BadPaddingException` 或解密后数据乱码

**可能原因**：
1. ❌ 使用了错误的加密模式 (ECB vs CBC)
2. ❌ IV向量不匹配或未正确传递
3. ❌ 密钥错误或已过期
4. ❌ 消息头解析错误导致截断

**排查步骤**：
```bash
# 1. 检查加密模式
grep -r "AES/ECB" src/  # 应该不存在

# 2. 打印IV和密钥 (调试用)
log.debug("IV: {}", Hex.encodeHexString(iv));
log.debug("Key: {}", Hex.encodeHexString(key));

# 3. 验证密钥长度
assert key.length == 16 : "Key must be 16 bytes";

# 4. 捕获详细异常
try {
    decrypt(...);
} catch (BadPaddingException e) {
    log.error("Padding error - likely wrong key or IV", e);
} catch (IllegalBlockSizeException e) {
    log.error("Block size error - data corruption", e);
}
```

### 6.2 设备ID匹配失败

**现象**：无法找到对应设备的会话，使用默认密钥解密失败

**可能原因**：
1. ❌ 消息头中设备ID字段长度定义错误 (应为48字节)
2. ❌ 设备ID编码问题 (ASCII vs UTF-8)
3. ❌ 设备ID包含不可见字符

**解决方案**：
```java
// 正确的设备ID提取方法
private String extractDeviceId(byte[] deviceIdBytes) {
    // 确保数组长度为48
    if (deviceIdBytes.length != 48) {
        log.warn("Unexpected device ID length: {}", deviceIdBytes.length);
    }
    
    // 去除末尾的0填充
    int len = deviceIdBytes.length;
    while (len > 0 && deviceIdBytes[len - 1] == 0) {
        len--;
    }
    
    // 使用ASCII解码 (设备序列号通常是ASCII)
    return new String(deviceIdBytes, 0, len, StandardCharsets.US_ASCII);
}
```

### 6.3 注册后仍解密失败

**现象**：注册成功，但后续消息解密失败

**可能原因**：
1. ❌ 注册响应中的会话密钥未正确保存
2. ❌ 密钥更新时机不对 (应立即生效还是下次消息生效)
3. ❌ 多设备共享同一个SessionContext

**调试方法**：
```java
// 在解密前打印使用的密钥
log.debug("Decrypting with key: {} for device: {}", 
    Hex.encodeHexString(currentKey), deviceId);

// 验证密钥是否已更新
if (context.isSessionExpired(86400000)) {
    log.warn("Session expired, need re-registration");
}
```

### 6.4 抓包分析示例

使用Wireshark或tcpdump抓取原始报文：

```bash
# Linux抓包
sudo tcpdump -i any port 7660 -w isup_capture.pcap

# 使用tshark解析
tshark -r isup_capture.pcap -T fields \
  -e frame.time \
  -e ip.src \
  -e tcp.payload \
  -Y "tcp.port == 7660"
```

**报文分析要点**：
1. 检查前4字节是否为 `53 55 50 49` (ISUP)
2. 检查版本字段是否为 `05 00`
3. 检查设备ID位置 (偏移24) 的48字节内容
4. 检查加密标志位 (偏移72) 是否为01
5. 提取IV向量 (偏移76) 的16字节
6. 对比加密前后的消息体长度变化

---

## 7. 附录

### 7.1 错误码定义

| 错误码 | 说明 |
|--------|------|
| 0 | 成功 |
| 1001 | 设备未注册 |
| 1002 | 设备认证失败 |
| 1003 | 会话已过期 |
| 1004 | 密钥无效 |
| 1005 | 消息格式错误 |
| 1006 | 不支持的命令 |
| 1007 | 参数错误 |
| 1008 | 系统内部错误 |

### 7.2 设备序列号格式

海康设备序列号通常为：
- **格式**：大写字母+数字组合
- **长度**：11-13位 (如：ABC12345678)
- **编码**：ASCII
- **存储**：在48字节字段中左对齐，右侧补0

示例：
```
原始序列号: "ABC12345678"
48字节表示: 41 42 43 31 32 33 34 35 36 37 38 00 00 ... (共48字节)
            A  B  C  1  2  3  4  5  6  7  8  \0 \0 ...
```

### 7.3 参考资源

- 海康威视官方网站：https://www.hikvision.com
- ISUP协议咨询：联系海康威视技术支持获取官方文档
- AES规范：FIPS PUB 197
- Java Cryptography Architecture文档

### 7.4 测试用例示例

```java
@Test
public void testEncryptionDecryption() throws Exception {
    byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    byte[] plaintext = "Hello ISUP v5.0!".getBytes(StandardCharsets.UTF_8);
    
    // 加密
    ISUPCryptoUtil.EncryptedData encrypted = ISUPCryptoUtil.encrypt(plaintext, key);
    
    // 解密
    byte[] decrypted = ISUPCryptoUtil.decrypt(
        encrypted.getCiphertext(), 
        key, 
        encrypted.getIV()
    );
    
    // 验证
    assertArrayEquals(plaintext, decrypted);
    assertNotNull(encrypted.getIV());
    assertEquals(16, encrypted.getIV().length);
}

@Test
public void testMessageHeaderSerialization() {
    ISUPMessageHeader header = new ISUPMessageHeader();
    header.setMagicNumber(0x53555049L);
    header.setVersion(0x0500);
    header.setCommandType(0x0101);
    header.setSequenceNo(1);
    header.setDeviceId("ABC12345678".getBytes(StandardCharsets.US_ASCII));
    header.setEncryptFlag(1);
    header.setIv(ISUPCryptoUtil.generateIV());
    
    byte[] bytes = header.toBytes();
    ISUPMessageHeader parsed = ISUPMessageHeader.fromBytes(bytes);
    
    assertEquals(header.getMagicNumber(), parsed.getMagicNumber());
    assertEquals(header.getVersion(), parsed.getVersion());
    assertEquals(header.getCommandType(), parsed.getCommandType());
    assertArrayEquals(header.getDeviceId(), parsed.getDeviceId());
    assertArrayEquals(header.getIv(), parsed.getIv());
}
```

---

## 修订历史

| 版本 | 日期 | 作者 | 说明 |
|------|------|------|------|
| 1.0 | 2024-01-15 | AI Assistant | 初始版本 |

---

**免责声明**：本文档仅供参考学习使用，实际产品对接请以海康威视官方技术文档和SDK为准。如有版权问题，请联系删除。
