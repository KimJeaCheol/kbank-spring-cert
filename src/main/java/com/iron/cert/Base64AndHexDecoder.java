package com.iron.cert;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

public class Base64AndHexDecoder {
    public static void main(String[] args) {
        // Base64 인코딩된 문자열
        String base64EncodedString = "%25EC%2597%2585%25EB%25AC%25B4%25EB%25AA%2585%2520%253A%2520%25EC%259D%25B4%25EC%25B2%25B4%25ED%2595%2598%25EA%25B8%25B0%0A--------------------------------------%0A%25EA%25B1%25B0%25EB%259E%2598%25EA%25B5%25AC%25EB%25B6%2584%20%3A%20%25EC%25A6%2589%25EC%258B%259C%25EC%259D%25B4%25EC%25B2%25B4%0A%25EC%25B6%259C%25EA%25B8%2588%25EC%259D%2580%25ED%2596%2589%25EB%25AA%2585%20%3A%20%25EC%25BC%2580%25EC%259D%25B4%25EB%25B1%2585%25ED%2581%25AC%0A%25EC%25B6%259C%25EA%25B8%2588%25EA%25B3%2584%25EC%25A2%258C%25EB%25B2%2588%25ED%2598%25B8%20%3A%20100-200-017751%0A%25EC%259E%2585%25EA%25B8%2588%25EC%259D%2580%25ED%2596%2589%25EB%25AA%2585%20%3A%20%25EC%258B%25A0%25ED%2595%259C%0A%25EC%259E%2585%25EA%25B8%2588%25EA%25B3%2584%25EC%25A2%258C%25EB%25B2%2588%25ED%2598%25B8%20%3A%2030112399182%0A%25EC%259E%2585%25EA%25B8%2588%25EC%2598%2588%25EA%25B8%2588%25EC%25A3%25BC%25EB%25AA%2585%20%3A%20%25EC%25A7%2596%25EC%25B7%258C%25EB%258B%25B4%0A%25EC%259D%25B4%25EC%25B2%25B4%25EA%25B8%2588%25EC%2595%25A1%20%3A%2030%2B%25EC%259B%2590%0A%25EC%2588%2598%25EC%2588%2598%25EB%25A3%258C%20%3A%200%2B%25EC%259B%2590%0A%25EB%2582%25B4%25ED%2586%25B5%25EC%259E%25A5%25ED%2591%259C%25EC%258B%259C%20%3A%20%25EC%25A7%2596%25EC%25B7%258C%25EB%258B%25B4%0A%25EC%259E%2585%25EA%25B8%2588%25ED%2586%25B5%25EC%259E%25A5%25ED%2591%259C%25EC%258B%259C%20%3A%20%25EC%259D%25B4%25EC%2595%2584%25EB%25A5%25B4%25EB%25AF%25B8%0A%25EC%25A7%2591%25EA%25B8%2588%2528CMS%2529%25EC%25BD%2594%25EB%2593%259C%20%3A%20%0A%25EC%259D%25B4%25EC%25B2%25B4%25EA%25B5%25AC%25EB%25B6%2584%20%3A%20%25EB%25AF%25B8%25EC%2584%25A4%25EC%25A0%2595%0A%25EB%25A9%2594%25EB%25AA%25A8%20%3A%20%0A%0A%25EA%25B2%2580%25EC%25A6%259D%25EA%25B0%2592%20%3A%20a083bf52dd043d01ef4b6d7202d3c00f%250A%25EA%25B1%25B0%25EB%259E%2598%25EC%259D%25BC%25EC%259E%2590%2520%253A%25202024.05.23%250A%25EA%25B1%25B0%25EB%259E%2598%25EC%259D%25BC%25EC%258B%259C%2520%253A%252008%253A53%253A34";
        
        try {
            base64EncodedString = URLDecoder.decode(base64EncodedString, "UTF-8");
            base64EncodedString = URLDecoder.decode(base64EncodedString, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // Base64 디코더 객체 생성
        // Base64.Decoder base64Decoder = Base64.getDecoder();
        
        // // Base64 디코딩 수행
        // byte[] base64DecodedBytes = base64Decoder.decode(base64EncodedString);
        // String base64DecodedString = new String(base64DecodedBytes);
        
        // Hexadecimal 디코딩 수행
        // byte[] hexDecodedBytes = DatatypeConverter.parseHexBinary(hexEncodedString);
        // String hexDecodedString = new String(hexDecodedBytes);
        
        // 결과 출력
        // System.out.println("Base64 Encoded String: " + base64EncodedString);
        System.out.println("Base64 Decoded String: " + base64EncodedString);
        
        // System.out.println("Hex Encoded String: " + hexEncodedString);
        //System.out.println("Hex Decoded String: " + hexDecodedString);

        // byte[] binaryData = hexStringToByteArray(hexEncodedString);

        // 여기에서 binaryData를 사용하여 필요한 처리를 할 수 있습니다.
        // 예를 들어, 인증서 파싱 등의 작업을 수행할 수 있습니다.
        
        // binaryData 출력 예시
        // for (byte b : binaryData) {
        //     System.out.printf("%02X ", b);
        // }
    }

    // 16진수 문자열을 바이트 배열로 변환하는 메서드
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
