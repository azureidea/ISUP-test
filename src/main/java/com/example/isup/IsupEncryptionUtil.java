package com.example.isup;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * ISUP v5.0 协议加密解密工具类
 * 对应《海康威视 ISUP 协议开发文档》v5.0 第 4.5 节 数据加密
 *
 * 支持加密算法：
 * - AES-128-CBC（ISUP v5.0）
 * - 不加密（默认）
 */
@Slf4j
public class IsupEncryptionUtil {

    /**
     * AES 密钥长度（128 位）
     */
    private static final int AES_KEY_LENGTH = 16;

    /**
     * AES IV 长度（128 位）
     */
    private static final int AES_IV_LENGTH = 16;

    /**
     * AES 加密变换模式（CBC 模式）
     */
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";

    /**
     * AES 算法名称
     */
    private static final String AES_ALGORITHM = "AES";

    /**
     * 加密数据
     * @param plainData 明文数据
     * @param key 加密密钥（16 字节）
     * @param iv IV 向量（16 字节）
     * @return 加密后的数据
     */
    public static byte[] encrypt(byte[] plainData, byte[] key, byte[] iv) {
        if (iv == null || iv.length != AES_IV_LENGTH) {
            throw new IllegalArgumentException("IV 向量必须为 16 字节");
        }
        return aesEncrypt(plainData, key, iv);
    }

    /**
     * 解密数据
     * @param encryptedData 加密数据
     * @param key 解密密钥（16 字节）
     * @param iv IV 向量（16 字节）
     * @return 解密后的明文数据
     */
    public static byte[] decrypt(byte[] encryptedData, byte[] key, byte[] iv) {
        if (iv == null || iv.length != AES_IV_LENGTH) {
            throw new IllegalArgumentException("IV 向量必须为 16 字节");
        }
        return aesDecrypt(encryptedData, key, iv);
    }

    /**
     * AES-CBC 加密
     * @param data 待加密数据
     * @param key 密钥（16 字节）
     * @param iv IV 向量（16 字节）
     * @return 加密后的数据
     */
    private static byte[] aesEncrypt(byte[] data, byte[] key, byte[] iv) {
        try {
            // 确保密钥长度为 16 字节
            byte[] validKey = ensureKeyLength(key, AES_KEY_LENGTH);

            SecretKeySpec keySpec = new SecretKeySpec(validKey, AES_ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            byte[] encrypted = cipher.doFinal(data);
            log.debug("AES-CBC 加密成功：原始长度={}, 加密后长度={}", data.length, encrypted.length);
            return encrypted;
        } catch (Exception e) {
            log.error("AES-CBC 加密失败", e);
            throw new RuntimeException("AES-CBC 加密失败", e);
        }
    }

    /**
     * AES-CBC 解密
     * @param data 待解密数据
     * @param key 密钥（16 字节）
     * @param iv IV 向量（16 字节）
     * @return 解密后的数据
     */
    private static byte[] aesDecrypt(byte[] data, byte[] key, byte[] iv) {
        try {
            // 确保密钥长度为 16 字节
            byte[] validKey = ensureKeyLength(key, AES_KEY_LENGTH);

            SecretKeySpec keySpec = new SecretKeySpec(validKey, AES_ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            byte[] decrypted = cipher.doFinal(data);
            log.debug("AES-CBC 解密成功：加密长度={}, 解密后长度={}", data.length, decrypted.length);
            return decrypted;
        } catch (Exception e) {
            log.error("AES-CBC 解密失败：key={}, iv={}", 
                    bytesToHex(ensureKeyLength(key, AES_KEY_LENGTH)), 
                    bytesToHex(iv));
            throw new RuntimeException("AES-CBC 解密失败", e);
        }
    }

    /**
     * 确保密钥长度为指定长度
     * @param key 原始密钥
     * @param targetLength 目标长度
     * @return 调整后的密钥
     */
    private static byte[] ensureKeyLength(byte[] key, int targetLength) {
        if (key == null) {
            throw new IllegalArgumentException("密钥不能为空");
        }

        if (key.length == targetLength) {
            return key;
        } else if (key.length > targetLength) {
            // 截断
            return Arrays.copyOf(key, targetLength);
        } else {
            // 补零
            byte[] result = new byte[targetLength];
            System.arraycopy(key, 0, result, 0, key.length);
            return result;
        }
    }

    /**
     * 从设备安全码生成密钥
     * ISUP v5.0 使用设备验证码的前 16 字节作为 AES 密钥
     * @param deviceCode 设备验证码（通常 48 字节）
     * @return 16 字节密钥
     */
    public static byte[] generateKeyFromDeviceCode(String deviceCode) {
        if (deviceCode == null || deviceCode.isEmpty()) {
            return generateDefaultKey();
        }
        byte[] codeBytes = deviceCode.getBytes();
        return ensureKeyLength(codeBytes, AES_KEY_LENGTH);
    }

    /**
     * 生成默认密钥（用于测试，实际使用应从配置或安全渠道获取）
     * @return 16 字节默认密钥
     */
    public static byte[] generateDefaultKey() {
        // 注意：实际应用中应使用安全的密钥生成和存储机制
        return "hik12345".getBytes(); // 8 字节，会自动补零到 16 字节
    }

    /**
     * 生成随机 IV 向量
     * @return 16 字节随机 IV
     */
    public static byte[] generateRandomIv() {
        byte[] iv = new byte[AES_IV_LENGTH];
        new java.security.SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
