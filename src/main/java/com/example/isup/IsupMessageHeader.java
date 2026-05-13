package com.example.isup;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * ISUP v5.0 协议消息头结构
 * 对应《海康威视 ISUP 协议开发文档》v5.0 第 4.2 节 消息头格式
 *
 * 消息头总长度：92 字节（固定）
 * 字节序：大端模式（Big-Endian）
 * 
 * V5.0 主要变化：
 * - 设备序列号从 8 字节扩展到 48 字节
 * - 增加 IV 向量字段（16 字节，用于 CBC 模式）
 * - 协议版本支持 0x05
 */
@Data
@Slf4j
public class IsupMessageHeader {

    /**
     * 消息头长度（固定为 92 字节）
     */
    public static final int HEADER_LENGTH = 92;

    /**
     * 起始标识（2 字节）：固定为 0x687A
     */
    private short startFlag = 0x687A;

    /**
     * 消息长度（4 字节）：整个消息的长度（包含消息头和消息体），不包括校验码
     */
    private int messageLength;

    /**
     * 协议版本（1 字节）：0x01-ISUP 2.0, 0x02-ISUP 3.0, 0x05-ISUP 5.0
     */
    private byte protocolVersion;

    /**
     * 保留位（1 字节）：固定为 0x00
     */
    private byte reserved = 0x00;

    /**
     * 消息类型（2 字节）：见 IsupMessageType 定义
     */
    private short messageType;

    /**
     * 序列号（4 字节）：消息的唯一标识，由发送方生成，响应消息需使用相同序列号
     */
    private int sequenceNumber;

    /**
     * 源设备 ID（48 字节）：发送方的设备序列号（ASCII 编码，不足补 0x00）
     * ISUP v5.0 中从 8 字节扩展到 48 字节
     */
    private String sourceDeviceId;

    /**
     * 目标设备 ID（48 字节）：接收方的设备序列号（ASCII 编码，不足补 0x00）
     * ISUP v5.0 中从 8 字节扩展到 48 字节
     */
    private String targetDeviceId;

    /**
     * 加密标志（1 字节）：0x00-不加密，0x01-AES-CBC 加密，0x02-RSA 加密
     * ISUP v5.0 使用 0x01 表示 AES-128-CBC 模式
     */
    private byte encryptionFlag;

    /**
     * IV 向量（16 字节）：AES-CBC 模式的初始化向量
     * 仅当加密标志为 0x01 时有效
     */
    private byte[] ivVector;

    /**
     * 保留位 2（12 字节）：固定为 0x00
     */
    private byte[] reserved2 = new byte[12];

    /**
     * 校验码（2 字节）：CRC16 校验（从消息头开始到消息体结束，不包括校验码本身）
     */
    private short crcCode;

    /**
     * 将消息头序列化为字节数组（大端模式）
     * @return 92 字节的消息头数组
     */
    public byte[] toBytes() {
        byte[] buffer = new byte[HEADER_LENGTH];
        int offset = 0;

        // 起始标识（2 字节，大端）
        buffer[offset++] = (byte) ((startFlag >> 8) & 0xFF);
        buffer[offset++] = (byte) (startFlag & 0xFF);

        // 消息长度（4 字节，大端）
        buffer[offset++] = (byte) ((messageLength >> 24) & 0xFF);
        buffer[offset++] = (byte) ((messageLength >> 16) & 0xFF);
        buffer[offset++] = (byte) ((messageLength >> 8) & 0xFF);
        buffer[offset++] = (byte) (messageLength & 0xFF);

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
     * @param data 字节数组
     * @param offset 起始偏移量
     * @return IsupMessageHeader 对象
     */
    public static IsupMessageHeader fromBytes(byte[] data, int offset) {
        if (data == null || data.length < offset + HEADER_LENGTH) {
            throw new IllegalArgumentException("数据长度不足：" + data.length + ", 需要至少 " + (offset + HEADER_LENGTH));
        }

        IsupMessageHeader header = new IsupMessageHeader();
        int pos = offset;

        // 起始标识（2 字节，大端）
        header.startFlag = (short) (((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF));
        if (header.startFlag != 0x687A) {
            log.warn("无效的起始标识：0x{:04X}", header.startFlag);
        }

        // 消息长度（4 字节，大端）
        header.messageLength = ((data[pos++] & 0xFF) << 24) |
                ((data[pos++] & 0xFF) << 16) |
                ((data[pos++] & 0xFF) << 8) |
                (data[pos++] & 0xFF);

        // 协议版本（1 字节）
        header.protocolVersion = data[pos++];

        // 保留位（1 字节）
        header.reserved = data[pos++];

        // 消息类型（2 字节，大端）
        header.messageType = (short) (((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF));

        // 序列号（4 字节，大端）
        header.sequenceNumber = ((data[pos++] & 0xFF) << 24) |
                ((data[pos++] & 0xFF) << 16) |
                ((data[pos++] & 0xFF) << 8) |
                (data[pos++] & 0xFF);

        // 源设备 ID（48 字节）
        byte[] sourceBytes = new byte[48];
        System.arraycopy(data, pos, sourceBytes, 0, 48);
        header.sourceDeviceId = new String(sourceBytes).replaceAll("\\x00+$", "").trim();
        pos += 48;

        // 目标设备 ID（48 字节）
        byte[] targetBytes = new byte[48];
        System.arraycopy(data, pos, targetBytes, 0, 48);
        header.targetDeviceId = new String(targetBytes).replaceAll("\\x00+$", "").trim();
        pos += 48;

        // 加密标志（1 字节）
        header.encryptionFlag = data[pos++];

        // IV 向量（16 字节）
        header.ivVector = new byte[16];
        System.arraycopy(data, pos, header.ivVector, 0, 16);
        pos += 16;

        // 保留位 2（12 字节）
        header.reserved2 = new byte[12];
        System.arraycopy(data, pos, header.reserved2, 0, 12);
        pos += 12;

        // CRC 校验码（2 字节，大端）
        header.crcCode = (short) (((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF));

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
