package org.anlib.cryptography.MD5;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** 
	 * Md5校验工具类 
	 * @author anLib 
	 */  
	public class MD5Util {  
	    private static final char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',  
	            'a', 'b', 'c', 'd', 'e', 'f'};  
	    
	    /** 
	     * MD5校验字符串 
	     * @param s String to be MD5 
	     * @return 'null' if cannot get MessageDigest 
	     */  
	    private static String getStringMD5(String s) {  
	        MessageDigest mdInst;  
	        try {  
	            // 获得MD5摘要算法的 MessageDigest 对象  
	            mdInst = MessageDigest.getInstance("MD5");  
	        } catch (NoSuchAlgorithmException e) {  
	            e.printStackTrace();  
	            return "";  
	        }  
	  
	        byte[] btInput = s.getBytes();  
	        // 使用指定的字节更新摘要  
	        mdInst.update(btInput);  
	        // 获得密文  
	        byte[] md = mdInst.digest();  
	        // 把密文转换成十六进制的字符串形式  
	        int length = md.length;  
	        char str[] = new char[length * 2];  
	        int k = 0;  
	        for (byte b : md) {  
	            str[k++] = hexDigits[b >>> 4 & 0xf];  
	            str[k++] = hexDigits[b & 0xf];  
	        }  
	        String strUp = new String(str).toUpperCase();
	        return strUp;  
	    }  

	    /**
	     * main函数
	     */
	    public static void main(String[] args) throws IOException {
	    	String str = "李兵123456";
	        String md5Str = getStringMD5(str);     
	        System.out.println("md5Str:"+md5Str); 
	    }  
	}  