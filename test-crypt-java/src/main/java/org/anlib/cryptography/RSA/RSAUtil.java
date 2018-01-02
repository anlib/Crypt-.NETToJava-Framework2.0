package org.anlib.cryptography.RSA;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

/**
 * RSA安全编码组件
 * 
 * @version 1.0
 * @since 1.0
 * @author 李兵
 */
public abstract class RSAUtil {
	public static final String KEY_ALGORITHM = "RSA";
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

	private static final String PUBLIC_KEY = "testRSAPublicKey李兵123456";
	private static final String PRIVATE_KEY = "testRSAPrivateKey李兵123456";

	/**
	 * 用私钥对信息生成数字签名
	 * 
	 * @param data
	 *            加密数据
	 * @param privateKey
	 *            私钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static String sign(byte[] data, String privateKey) throws Exception {
		// 解密由base64编码的私钥
		byte[] keyBytes = decryptBASE64(privateKey);

		// 构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取私钥匙对象
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 用私钥对信息生成数字签名
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(data);

		return encryptBASE64(signature.sign());
	}

	/**
	 * 校验数字签名
	 * 
	 * @param data
	 *            加密数据
	 * @param publicKey
	 *            公钥
	 * @param sign
	 *            数字签名
	 * 
	 * @return 校验成功返回true 失败返回false
	 * @throws Exception
	 * 
	 */
	public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {

		// 解密由base64编码的公钥
		byte[] keyBytes = decryptBASE64(publicKey);

		// 构造X509EncodedKeySpec对象
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取公钥匙对象
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(data);

		// 验证签名是否正常
		return signature.verify(decryptBASE64(sign));
	}

	/**
	 * 解密<br>
	 * 用私钥解密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);

		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}

	/**
	 * 解密<br>
	 * 用公钥解密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}

	/**
	 * 加密<br>
	 * 用公钥加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
		// 对公钥解密
		byte[] keyBytes = decryptBASE64(key);

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}

	/**
	 * 加密<br>
	 * 用私钥加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);

		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}

	/**
	 * 取得私钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PRIVATE_KEY);

		return encryptBASE64(key.getEncoded());
	}

	/**
	 * 取得公钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);

		return encryptBASE64(key.getEncoded());
	}

	/**
	 * 初始化密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(1024);

		KeyPair keyPair = keyPairGen.generateKeyPair();

		// 公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

		// 私钥
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		Map<String, Object> keyMap = new HashMap<String, Object>(2);

		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	/**
	 * BASE64解密
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptBASE64(String key) throws Exception {
		return (Base64.decodeBase64(key.getBytes()));
	}

	/**
	 * BASE64加密
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encryptBASE64(byte[] key) throws Exception {
		return (new String(Base64.encodeBase64(key)));
	}

	/**
	 * 生成公钥私钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static Map<String, String> CreatePublicKeyAndPrivateKey() throws Exception {
		Map<String, Object> keyMap = RSAUtil.initKey();
		String publicKey = RSAUtil.getPublicKey(keyMap);
		String privateKey = RSAUtil.getPrivateKey(keyMap);
		// 构造map返回
		Map<String, String> keyStrMap = new HashMap<String, String>();
		keyStrMap.put("publicKey", publicKey);
		keyStrMap.put("privateKey", privateKey);
		return keyStrMap;
	}

	/**
	 * 私钥签名
	 * 
	 * @param privateKey
	 * @param inputStr
	 * @return String sign
	 * @throws Exception
	 */
	public static String privateKeySign(String privateKey, String inputStr) throws Exception {
		byte[] data = inputStr.getBytes();
		// 产生签名
		String sign = RSAUtil.sign(data, privateKey);
		return sign;
	}

	/**
	 * 公钥验签
	 * 
	 * @param publicKey
	 * @param sign
	 * @param inputStr
	 * @return boolean status(true or false)
	 * @throws Exception
	 */
	public static boolean publicKeyCheckSign(String publicKey, String sign, String inputStr) throws Exception {
		byte[] data = inputStr.getBytes();
		// 验证签名
		boolean status = RSAUtil.verify(data, publicKey, sign);
		return status;
	}

	/**
	 * main函数 测试方法
	 */
	public static void main(String[] args) throws Exception {
		// 生成公钥私钥：
		Map<String, String> keyStrMap = CreatePublicKeyAndPrivateKey();
		String publicKey = keyStrMap.get("publicKey");
		String privateKey = keyStrMap.get("privateKey");
		System.err.println("-----------公钥加密——私钥解密-----------");
		// 用特定的公钥进行测试：
		publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC48Emk40lqa7WAd2M32paVW5FdCEnLuuRz4Iz2xCK7ILTP7EGJndkBsq0+33FsWx3h4I+J6mat0RUcojOof0kBrWoc+V7fxazMSEsY58RyUdnpkjgFUJNo/3BclJvKJAat7Wj6ZDuAvEa4zvFqaEJdHPZvuH2hdYUm+ixcDj+pwQIDAQAB";
		privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALjwSaTjSWprtYB3YzfalpVbkV0IScu65HPgjPbEIrsgtM/sQYmd2QGyrT7fcWxbHeHgj4nqZq3RFRyiM6h/SQGtahz5Xt/FrMxISxjnxHJR2emSOAVQk2j/cFyUm8okBq3taPpkO4C8RrjO8WpoQl0c9m+4faF1hSb6LFwOP6nBAgMBAAECgYEAkQOx635hqfYNW0/CWCCp5THo+RcvrnW8/3P7dN/1D+Ckh0mNVliUufUeTeetq7aC5wRL6WwI2ZDSSiKR+TTdzAH79ADeukYF8t7xlpIXUBWdf/HPqQTdkpVf+8xguEWbZay3FhUoMbDrNwrHJnVeJII23m71FxpQl2R0xIzjvwECQQDn/9e/MSMkrQzyuOl+ncWvRUHsm15NkfGv1MU+jzd9JfGJPX6pj/eZY2ixG7i1daqFd0qhsPORn9RuiknrlfyxAkEAzBIcZNUiGHjNEvbw0YLsRohVIow2w3KIDKg2tL3x4jm3TfP79GK4YZ3qEXq5SGjJfEkENhdl7IFq7iDyjHiCEQJAU3rOCTAHM0VJqXU8H6Fp5r2HETp+3m6rhteK+g3Sq6ehl/6WuzDgqUMKAuC0wCbM6yWXp0LjAf1/FR+RpcHcoQJAa+DjG7bECHXLy0u5sLfqWbr2boX66UVhgHdoPBHxjar/KPli5yVM3WXSeB0NV6b1ZHtg+4tQ+T7NHUdTkUifUQJBAOQXXaEHI53epuRA6kWki8QVRU1nnV2GqqYJqAZVbReFonQHZvbSImeGAv2IBjEIHgjPQHgLzwoCTSYnpAry9Kc=";
		System.out.println("公钥: \r" + publicKey);
		System.out.println("私钥： \r" + privateKey);
		String inputStr = "李兵123456";// 要加密的字符串
		System.out.println("加密前: " + inputStr);
		byte[] data = inputStr.getBytes();
		byte[] encodedData = encryptByPublicKey(data, publicKey);
		// Base64
		String base64EnStr = new Base64().encodeAsString(encodedData);
		// 测试base64结果
		// base64EnStr = "";
		System.out.println("加密后: " + base64EnStr);
		encodedData = new Base64().decode(base64EnStr);
		byte[] decodedData = RSAUtil.decryptByPrivateKey(encodedData, privateKey);
		String outputStr = new String(decodedData);
		System.out.println("解密后: " + outputStr);
		System.out.println("私钥签名——公钥验证签名");
		// 产生签名
		String sign = RSAUtil.sign(encodedData, privateKey);
		sign = "FK6wgFHKybAWdUQ5qjrNRgQR1Up/zvFmJ3yMbpj8JatRm6P4GVE1DQtPtv6eB5GjKMdZdf/2puIKWSNLnvXQDJdpQ/wD2MdN4mW5qlNjgXlEUjA11GOiBhAyV2UNraVv8UP9T8w36H2Ni/XhwTs01DoroUFR+Ta3Cz/ZG7LsVbk=";
		System.out.println("签名:\r" + sign);
		// 验证签名
		boolean status = publicKeyCheckSign(publicKey, sign, inputStr);
		System.out.println("状态:\r" + status);
	}
}