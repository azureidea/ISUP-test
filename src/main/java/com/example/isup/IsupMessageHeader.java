package com.example.isup;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * ISUP v5.0 协议消息头结构
 * 基于实际设备报文反推的真实格式（与官方文档不同）
 *
 * 实际消息头格式（变长）：
 * [0-1]   协议版本 (2 字节，大端) - 0x0101 = V5.0
 * [2-3]   消息类型 (2 字节，大端) - 0x0009 = 注册请求
 * [4-N]   源设备序列号 (变长 ASCII) - 如"GA7572936"
 * [N+1]   下一字段长度 (1 字节)
 * [N+2-M] 设备标识/验证码 (变长 ASCII)
 * [M+1]   保留字节 (1 字节，0x00)
 * [M+2-M+5] 序列号 (4 字节，大端)
 * [M+6]   加密标志 (1 字节) - 0x00=不加密，0x01=AES-CBC
 * [M+7-M+22] IV 向量 (16 字节)
 * 后续为加密的消息体
 */
@Data
@Slf4j
public class IsupMessageHeader {

    /**
     * 最小消息头长度（根据实际报文）
     */
    public static final int MIN_HEADER_LENGTH = 36;

    /**
     * 协议版本（2 字节）：0x0101-ISUP 5.0
     */
    private short protocolVersion;

    /**
     * 消息类型（2 字节）：见 IsupMessageType 定义
     */
    private short messageType;

    /**
     * 源设备序列号（变长 ASCII）
     */
    private String sourceDeviceId;

    /**
     * 设备验证码/标识（变长 ASCII）
     */
    private String deviceCode;

    /**
     * 消息序列号（4 字节）
     */
    private int sequenceNumber;

    /**
     * 加密标志（1 字节）：0x00-不加密，0x01-AES-CBC
     */
    private byte encryptionFlag;

    /**
     * IV 向量（16 字节）：AES-CBC 模式的初始化向量
     */
    private byte[] ivVector;

    /**
     * 消息体长度（用于计算总长度）
     */
    private int bodyLength;

    /**
     * 校验码（2 字节）：CRC16
     */
    private short crcCode;

    /**
     * 将消息头序列化为字节数组（大端模式）
     * @return 92 字节的消息头数组
     */
    public byte[] toBytes() {
        byte[] buffer = new byte[HEADER_LENGTH];
        int offset = 0;

        // 协议版本（1 字节）
        buffer[offset++] = protocolVersion;

        // 保留位（1 字节）
        buffer[offset++] = reserved;

        // 消息类型（2 字节，大端）
        buffer[offset++] = (byte) ((messageType >> 8) & 0xFF);
        buffer[offset++] = (byte) (messageType & 0xFF);

        // 序列号（4 字节，大端）
        buffer[offset++] = (byte) ((sequenceNumber >> 24) & 0xFF);
        buffer[offset++] = (byte) ((sequenceNumber >> 16) & 0xFF);
        buffer[offset++] = (byte) ((sequenceNumber >> 8) & 0xFF);
        buffer[offset++] = (byte) (sequenceNumber & 0xFF);

        // 源设备 ID（48 字节，ASCII 编码，不足补 0）
        byte[] sourceBytes = sourceDeviceId != null ? sourceDeviceId.getBytes() : new byte[0];
        for (int i = 0; i < 48; i++) {
            buffer[offset++] = i < sourceBytes.length ? sourceBytes[i] : 0x00;
        }

        // 目标设备 ID（48 字节，ASCII 编码，不足补 0）
        byte[] targetBytes = targetDeviceId != null ? targetDeviceId.getBytes() : new byte[0];
        for (int i = 0; i < 48; i++) {
            buffer[offset++] = i < targetBytes.length ? targetBytes[i] : 0x00;
        }

        // 加密标志（1 字节）
        buffer[offset++] = encryptionFlag;

        // IV 向量（16 字节）
        if (ivVector != null && ivVector.length == 16) {
            System.arraycopy(ivVector, 0, buffer, offset, 16);
            offset += 16;
        } else {
            // 默认 IV 为全 0
            for (int i = 0; i < 16; i++) {
                buffer[offset++] = 0x00;
            }
        }

        // 保留位 2（12 字节）
        for (int i = 0; i < 12; i++) {
            buffer[offset++] = 0x00;
        }

        // CRC 校验码（2 字节，大端）- 待计算
        buffer[offset++] = (byte) ((crcCode >> 8) & 0xFF);
        buffer[offset++] = (byte) (crcCode & 0xFF);

        return buffer;
    }

    /**
     * 从字节数组解析消息头（大端模式）
     * ISUP v5.0 实际消息头结构（变长，基于真实报文反推）：
     * [0-1]   协议版本 (2 字节) - 0x0101
     * [2-3]   消息类型 (2 字节)
     * [4-N]   源设备序列号 (变长 ASCII，直到遇到长度字段)
     * [N+1]   设备码长度 (1 字节)
     * [N+2-M] 设备码 (变长 ASCII)
     * [M+1]   保留字节 (1 字节，0x00)
     * [M+2-M+5] 序列号 (4 字节) - 注意：这里的序列号可能包含 ASCII 字符
     * [M+6]   加密标志 (1 字节) - 0x00=不加密，0x01=AES-CBC, 0x02=已加密
     * [M+7-M+22] IV 向量 (16 字节)
     */
    public static IsupMessageHeader fromBytes(byte[] data, int offset) {
        if (data == null || data.length < offset + MIN_HEADER_LENGTH) {
            throw new IllegalArgumentException("数据长度不足：" + data.length + ", 需要至少 " + (offset + MIN_HEADER_LENGTH));
        }

        IsupMessageHeader header = new IsupMessageHeader();
        int pos = offset;

        // [0-1] 协议版本（2 字节，大端）
        header.protocolVersion = (short) (((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF));

        // [2-3] 消息类型（2 字节，大端）
        header.messageType = (short) (((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF));

        // [4-N] 源设备序列号（变长，读取直到遇到非 ASCII 可打印字符或长度字段）
        StringBuilder deviceId = new StringBuilder();
        while (pos < data.length) {
            byte b = data[pos];
            // 如果是可打印 ASCII 字符（0x20-0x7E），继续读取
            if (b >= 0x20 && b <= 0x7E) {
                deviceId.append((char) b);
                pos++;
            } else {
                break;
            }
        }
        header.sourceDeviceId = deviceId.toString();

        // [N+1] 设备码长度（1 字节）
        if (pos >= data.length) {
            throw new IllegalArgumentException("数据不完整，缺少设备码长度字段");
        }
        int deviceCodeLen = data[pos++] & 0xFF;

        // [N+2-M] 设备码（变长 ASCII）
        if (pos + deviceCodeLen > data.length) {
            throw new IllegalArgumentException("数据不完整，设备码长度超出范围");
        }
        byte[] codeBytes = new byte[deviceCodeLen];
        System.arraycopy(data, pos, codeBytes, 0, deviceCodeLen);
        header.deviceCode = new String(codeBytes).trim();
        pos += deviceCodeLen;

        // [M+1] 保留字节（1 字节）
        if (pos >= data.length) {
            throw new IllegalArgumentException("数据不完整，缺少保留字节");
        }
        pos++; // 跳过保留字节

        // [M+2-M+5] 序列号（4 字节，大端）
        // 注意：在实际报文中，这个字段可能包含 ASCII 字符（如"GA75"）
        // 这是海康的非标准实现
        if (pos + 4 > data.length) {
            throw new IllegalArgumentException("数据不完整，缺少序列号");
        }
        header.sequenceNumber = ((data[pos++] & 0xFF) << 24) |
                ((data[pos++] & 0xFF) << 16) |
                ((data[pos++] & 0xFF) << 8) |
                (data[pos++] & 0xFF);

        // [M+6] 加密标志（1 字节）
        // 注意：在实际报文中，加密标志可能是 0x02 而不是 0x01
        if (pos >= data.length) {
            throw new IllegalArgumentException("数据不完整，缺少加密标志");
        }
        
        // 查找真正的加密标志位置
        // 策略：寻找后面紧跟 16 字节二进制数据的位置
        int encFlagPos = -1;
        for (int i = pos; i < Math.min(pos + 20, data.length - 16); i++) {
            byte flag = data[i];
            // 检查是否是合理的加密标志（0x00, 0x01, 0x02）
            if (flag == 0x00 || flag == 0x01 || flag == 0x02) {
                // 检查后续 16 字节是否看起来像 IV（少量可打印字符）
                byte[] potentialIv = java.util.Arrays.copyOfRange(data, i + 1, i + 17);
                int printableCount = 0;
                for (byte b : potentialIv) {
                    if (b >= 0x20 && b <= 0x7E) printableCount++;
                }
                if (printableCount <= 6) {
                    encFlagPos = i;
                    break;
                }
            }
        }
        
        if (encFlagPos < 0) {
            // 如果找不到，使用当前位置
            encFlagPos = pos;
        }
        
        header.encryptionFlag = data[encFlagPos++];

        // [M+7-M+22] IV 向量（16 字节）
        if (encFlagPos + 16 > data.length) {
            throw new IllegalArgumentException("数据不完整，缺少 IV 向量");
        }
        header.ivVector = new byte[16];
        System.arraycopy(data, encFlagPos, header.ivVector, 0, 16);
        pos = encFlagPos + 16;

        // 记录消息头实际占用的长度
        header.bodyLength = pos - offset;

        return header;
    }

    /**
     * 打印消息头详细信息（用于调试）
     */
    public void printDebugInfo() {
        log.debug("===== ISUP 消息头 =====");
        log.debug("起始标识：0x{:04X}", startFlag);
        log.debug("消息长度：{}", messageLength);
        log.debug("协议版本：0x{:02X} (ISUP {})", protocolVersion, getVersionDescription());
        log.debug("消息类型：0x{:04X} ({})", messageType, IsupMessageType.getMessageTypeDescription(messageType));
        log.debug("序列号：{}", sequenceNumber);
        log.debug("源设备 ID: {}", sourceDeviceId);
        log.debug("目标设备 ID: {}", targetDeviceId);
        log.debug("加密标志：0x{:02X} ({})", encryptionFlag, getEncryptionDescription());
        if (encryptionFlag == 0x01 && ivVector != null) {
            log.debug("IV 向量：{}", bytesToHex(ivVector));
        }
        log.debug("CRC 校验码：0x{:04X}", crcCode);
        log.debug("=====================");
    }

    private String getVersionDescription() {
        switch (protocolVersion) {
            case 0x01: return "2.0";
            case 0x02: return "3.0";
            case 0x05: return "5.0";
            default: return "未知 (" + protocolVersion + ")";
        }
    }

    private String getEncryptionDescription() {
        switch (encryptionFlag) {
            case 0x00: return "不加密";
            case 0x01: return "AES-CBC";
            case 0x02: return "RSA";
            default: return "未知 (" + encryptionFlag + ")";
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
