package com.byx.encryptapp.services;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.springframework.beans.factory.annotation.Value;
import org.w3c.dom.Document;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class EncryptDocService {
    @Value("${signature.key.alias}")
    private String keyAlias;

    private static Crypto crypto;
    public EncryptDocService() throws Exception {
        // Initialize WSSConfig to ensure the correct operation
        WSSConfig.init();
        // Initialize the crypto instance with the necessary properties
        // Replace the null parameters with actual values
        crypto =  CryptoFactory.getInstance("wss40.properties");
    }
    public static Document includeEncryption(Document doc, String keyAlias) throws Exception {
        return includeEncryption(doc, keyAlias, WSConstants.ISSUER_SERIAL,
                WSConstants.TRIPLE_DES, null,
                WSConstants.KEYTRANSPORT_RSAOAEP, null);
    }
    public static Document includeEncryption(Document doc, String keyAlias,
                                             int keyIdentifierType, String encAlgorithm,
                                             String digestAlgorithm, String keyEncAlgo,
                                             WSEncryptionPart[] parts) throws Exception {
        WSSecHeader secHeader = new WSSecHeader(doc);
        if (secHeader.isEmpty()) {
            secHeader.insertSecurityHeader();
        }
        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo(keyAlias);
        builder.setKeyIdentifierType(keyIdentifierType);
        builder.setSymmetricEncAlgorithm(encAlgorithm);
        if (digestAlgorithm != null) {
            builder.setDigestAlgorithm(digestAlgorithm);
        }
        builder.setKeyEncAlgo(keyEncAlgo);
        if (parts != null) {
            for (WSEncryptionPart part : parts) {
                builder.getParts().add(part);
            }
        }
        // Create a KeyGenerator instance for AES algorithm
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        // Initialize the KeyGenerator with a specified key size
        keyGenerator.init(256); // You can use 128, 192, or 256 bits

        // Generate the secret key
        SecretKey secretKey = keyGenerator.generateKey();

        return builder.build(crypto,secretKey);
    }
}
