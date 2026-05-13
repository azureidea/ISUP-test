package com.example.isup;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * 海康 ISUP v5.0 协议 Netty 处理器
 * 基于实际设备报文反推的协议解析逻辑（与官方文档不同）
 *
 * 协议特点（v5.0，实际实现）：
 * - 字节序：大端模式（Big-Endian）
 * - 消息头变长（约 36+ 字节），不是固定的 92 字节
 * - 无起始标识字段
 * - 设备 ID 和设备码是变长的 ASCII 字符串
 * - AES-128-CBC 加密（IV 向量在消息头中）
 */
@Slf4j
public class IsupServerHandler extends ChannelInboundHandlerAdapter {

    /**
     * 最小消息长度（根据实际报文）
     */
    private static final int MIN_MESSAGE_LENGTH = 36;

    /**
     * 最大消息长度限制（防止恶意攻击）
     */
    private static final int MAX_MESSAGE_LENGTH = 1024 * 1024; // 1MB

    /**
     * 设备会话管理器（实际项目中应注入 Spring Bean）
     */
    private IsupSessionManager sessionManager;

    public IsupServerHandler() {
        this.sessionManager = new IsupSessionManager();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof ByteBuf)) {
            super.channelRead(ctx, msg);
            return;
        }

        ByteBuf buffer = (ByteBuf) msg;

        try {
            buffer.order(ByteOrder.BIG_ENDIAN);

            while (buffer.readableBytes() >= IsupMessageHeader.MIN_HEADER_LENGTH) {
                buffer.markReaderIndex();

                // 读取整个报文（包括消息头和消息体）
                byte[] data = new byte[buffer.readableBytes()];
                buffer.readBytes(data);

                // 解析消息头
                IsupMessageHeader header = IsupMessageHeader.fromBytes(data, 0);

                log.info("解析 ISUP 消息：类型=0x{:04X} ({}), 设备={}, 序列号={}",
                        header.getMessageType(),
                        IsupMessageType.getMessageTypeDescription(header.getMessageType()),
                        header.getSourceDeviceId(),
                        header.getSequenceNumber());

                // 处理消息（实际项目中需要根据具体业务逻辑实现）
                handleMessage(ctx, header, null);
            }
        } catch (Exception e) {
            log.error("处理 ISUP 消息时发生异常", e);
            ctx.close();
        } finally {
            buffer.release();
        }
    }

    private void handleMessage(ChannelHandlerContext ctx, IsupMessageHeader header, byte[] body) {
        short messageType = header.getMessageType();

        log.debug("收到 ISUP 消息：类型={}, 序列号={}, 源={}",
                IsupMessageType.getMessageTypeDescription(messageType),
                header.getSequenceNumber(),
                header.getSourceDeviceId());

        switch (messageType) {
            case IsupMessageType.DEVICE_REGISTER_REQ:
                handleDeviceRegister(ctx, header, body);
                break;
            case IsupMessageType.HEARTBEAT_REQ:
                handleHeartbeat(ctx, header, body);
                break;
            case IsupMessageType.DEVICE_UNREGISTER_REQ:
                handleDeviceUnregister(ctx, header, body);
                break;
            case IsupMessageType.ALARM_INPUT_NOTIFY:
                handleAlarmInput(ctx, header, body);
                break;
            case IsupMessageType.STREAM_FORWARD_NOTIFY:
                handleStreamForward(ctx, header, body);
                break;
            default:
                log.warn("未处理的 ISUP 消息类型：0x{:04X} ({})", messageType, 
                        IsupMessageType.getMessageTypeDescription(messageType));
                sendErrorResponse(ctx, header, (short) 0x0100, "Unsupported message type");
        }
    }

    private void handleDeviceRegister(ChannelHandlerContext ctx, IsupMessageHeader header, byte[] body) {
        log.info("处理设备注册请求：{}", header.getSourceDeviceId());

        try {
            if (body.length < 100) {
                log.error("注册请求体长度不足：{}", body.length);
                sendErrorResponse(ctx, header, (short) 0x0200, "Invalid register body length");
                return;
            }

            int offset = 0;
            byte[] serialBytes = Arrays.copyOfRange(body, offset, Math.min(offset + 48, body.length));
            String deviceSerial = new String(serialBytes).replaceAll("\\x00+$", "").trim();
            offset += 48;

            byte[] codeBytes = Arrays.copyOfRange(body, offset, Math.min(offset + 48, body.length));
            String deviceCode = new String(codeBytes).replaceAll("\\x00+$", "").trim();
            offset += 48;

            byte deviceType = body[offset++];
            int channelCount = ((body[offset++] & 0xFF) << 8) | (body[offset++] & 0xFF);
            byte protocolVersion = body[offset++];

            IsupDevice device = new IsupDevice();
            device.setDeviceSerial(deviceSerial);
            device.setDeviceCode(deviceCode);
            device.setDeviceType(deviceType);
            device.setChannelCount(channelCount);
            device.setProtocolVersion(protocolVersion);
            device.setIpAddress(ctx.channel().remoteAddress().toString().substring(1).split(":")[0]);
            device.setRegisterTime(System.currentTimeMillis());
            device.setLastHeartbeatTime(System.currentTimeMillis());
            device.setOnline(true);

            if (body.length > offset + 4) {
                device.setCapabilities(
                        ((body[offset++] & 0xFF) << 24) |
                        ((body[offset++] & 0xFF) << 16) |
                        ((body[offset++] & 0xFF) << 8) |
                        (body[offset++] & 0xFF)
                );
            }

            sessionManager.registerDevice(device, ctx.channel());

            log.info("设备注册成功：{}, 类型={}, 通道数={}, 能力={}",
                    deviceSerial, deviceType, channelCount, device.getCapabilitiesDescription());

            sendDeviceRegisterResponse(ctx, header, device);

        } catch (Exception e) {
            log.error("处理设备注册失败", e);
            sendErrorResponse(ctx, header, (short) 0x0201, "Register processing error: " + e.getMessage());
        }
    }

    private void sendDeviceRegisterResponse(ChannelHandlerContext ctx, IsupMessageHeader requestHeader, IsupDevice device) {
        IsupMessageHeader responseHeader = new IsupMessageHeader();
        responseHeader.setMessageType(IsupMessageType.DEVICE_REGISTER_RESP);
        responseHeader.setSequenceNumber(requestHeader.getSequenceNumber());
        responseHeader.setSourceDeviceId("PLATFORM"); // 平台标识
        responseHeader.setProtocolVersion((short) 0x0101);
        responseHeader.setEncryptionFlag((byte) 0x00);

        byte[] responseBody = new byte[52];
        int offset = 0;
        responseBody[offset++] = 0x00;
        responseBody[offset++] = 0x00;

        byte[] platformId = "VMP_PLATFORM".getBytes();
        for (int i = 0; i < 48; i++) {
            responseBody[offset++] = i < platformId.length ? platformId[i] : 0x00;
        }

        sendMessage(ctx, responseHeader, responseBody);
    }

    private void handleHeartbeat(ChannelHandlerContext ctx, IsupMessageHeader header, byte[] body) {
        String deviceId = header.getSourceDeviceId();
        log.debug("收到心跳：{}", deviceId);

        IsupDevice device = sessionManager.getDevice(deviceId);
        if (device != null) {
            device.setLastHeartbeatTime(System.currentTimeMillis());
        } else {
            log.warn("收到未知设备的心跳：{}", deviceId);
        }

        IsupMessageHeader responseHeader = new IsupMessageHeader();
        responseHeader.setMessageType(IsupMessageType.HEARTBEAT_RESP);
        responseHeader.setSequenceNumber(header.getSequenceNumber());
        responseHeader.setSourceDeviceId("PLATFORM");
        responseHeader.setProtocolVersion((short) 0x0101);
        responseHeader.setEncryptionFlag((byte) 0x00);

        sendMessage(ctx, responseHeader, new byte[0]);
    }

    private void handleDeviceUnregister(ChannelHandlerContext ctx, IsupMessageHeader header, byte[] body) {
        String deviceId = header.getSourceDeviceId();
        log.info("处理设备注销：{}", deviceId);

        sessionManager.unregisterDevice(deviceId);

        IsupMessageHeader responseHeader = new IsupMessageHeader();
        responseHeader.setMessageType(IsupMessageType.DEVICE_UNREGISTER_RESP);
        responseHeader.setSequenceNumber(header.getSequenceNumber());
        responseHeader.setSourceDeviceId("PLATFORM");
        responseHeader.setProtocolVersion((short) 0x0101);
        responseHeader.setEncryptionFlag((byte) 0x00);

        byte[] responseBody = new byte[2];
        responseBody[0] = 0x00;
        responseBody[1] = 0x00;

        sendMessage(ctx, responseHeader, responseBody);
    }

    private void handleAlarmInput(ChannelHandlerContext ctx, IsupMessageHeader header, byte[] body) {
        String deviceId = header.getSourceDeviceId();
        log.info("收到报警输入：{}", deviceId);

        IsupMessageHeader responseHeader = new IsupMessageHeader();
        responseHeader.setMessageType(IsupMessageType.ALARM_INPUT_ACK);
        responseHeader.setSequenceNumber(header.getSequenceNumber());
        responseHeader.setSourceDeviceId("PLATFORM");

        byte[] responseBody = new byte[2];
        responseBody[0] = 0x00;
        responseBody[1] = 0x00;

        sendMessage(ctx, responseHeader, responseBody);
    }

    private void handleStreamForward(ChannelHandlerContext ctx, IsupMessageHeader header, byte[] body) {
        String deviceId = header.getSourceDeviceId();
        log.info("收到流转发通知：{}", deviceId);

        IsupMessageHeader responseHeader = new IsupMessageHeader();
        responseHeader.setMessageType(IsupMessageType.HEARTBEAT_RESP);
        responseHeader.setSequenceNumber(header.getSequenceNumber());
        responseHeader.setSourceDeviceId("PLATFORM");

        byte[] responseBody = new byte[2];
        responseBody[0] = 0x00;
        responseBody[1] = 0x00;

        sendMessage(ctx, responseHeader, responseBody);
    }

    private void sendErrorResponse(ChannelHandlerContext ctx, IsupMessageHeader requestHeader,
                                   short errorCode, String errorMessage) {
        log.warn("发送错误响应：code={}, msg={}", errorCode, errorMessage);

        IsupMessageHeader responseHeader = new IsupMessageHeader();
        responseHeader.setMessageType((short) (requestHeader.getMessageType() + 1));
        responseHeader.setSequenceNumber(requestHeader.getSequenceNumber());
        responseHeader.setSourceDeviceId("PLATFORM");
        responseHeader.setProtocolVersion((short) 0x0101);
        responseHeader.setEncryptionFlag((byte) 0x00);

        byte[] errorBody = errorMessage.getBytes();
        byte[] responseBody = new byte[2 + errorBody.length];
        responseBody[0] = (byte) ((errorCode >> 8) & 0xFF);
        responseBody[1] = (byte) (errorCode & 0xFF);
        System.arraycopy(errorBody, 0, responseBody, 2, errorBody.length);

        sendMessage(ctx, responseHeader, responseBody);
    }

    private void sendMessage(ChannelHandlerContext ctx, IsupMessageHeader header, byte[] body) {
        try {
            byte[] headerBytes = header.toBytes();

            if (body != null && body.length > 0) {
                byte[] crcData = new byte[headerBytes.length + body.length];
                System.arraycopy(headerBytes, 0, crcData, 0, headerBytes.length);
                System.arraycopy(body, 0, crcData, headerBytes.length, body.length);

                short crc = (short) IsupCrcUtil.calculateCrc16(crcData);
                header.setCrcCode(crc);

                headerBytes = header.toBytes();

                ByteBuf buffer = ctx.alloc().buffer(headerBytes.length + body.length + 2);
                buffer.writeBytes(headerBytes);
                buffer.writeBytes(body);
                buffer.writeShort(crc);

                ctx.writeAndFlush(buffer);

                log.debug("发送 ISUP 消息：类型={}, 序列号={}, 长度={}",
                        IsupMessageType.getMessageTypeDescription(header.getMessageType()),
                        header.getSequenceNumber(),
                        headerBytes.length + body.length + 2);
            } else {
                // 无消息体的情况（如心跳响应）
                ByteBuf buffer = ctx.alloc().buffer(headerBytes.length);
                buffer.writeBytes(headerBytes);
                ctx.writeAndFlush(buffer);
                
                log.debug("发送 ISUP 消息（无消息体）：类型={}, 序列号={}",
                        IsupMessageType.getMessageTypeDescription(header.getMessageType()),
                        header.getSequenceNumber());
            }

        } catch (Exception e) {
            log.error("发送 ISUP 消息失败", e);
            throw e; // Re-throw to let caller handle it
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        log.info("客户端连接：{}", ctx.channel().remoteAddress());
        super.channelActive(ctx);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("客户端断开：{}", ctx.channel().remoteAddress());
        sessionManager.cleanupDisconnectedDevice(ctx.channel());
        super.channelInactive(ctx);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error("连接异常：{}", ctx.channel().remoteAddress(), cause);
        ctx.close();
    }
}
