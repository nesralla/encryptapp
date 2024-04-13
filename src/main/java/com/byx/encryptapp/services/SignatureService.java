package com.byx.encryptapp.services;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;



@Component
public class SignatureService {

    @Value("${signature.key.alias}")
    private String keyAlias;

    private final Crypto crypto;

    public SignatureService() throws Exception {
        // Initialize WSSConfig to ensure the correct operation
        WSSConfig.init();
        // Initialize the crypto instance with the necessary properties
        // Replace the null parameters with actual values
        this.crypto =  CryptoFactory.getInstance("wss40.properties");
    }

    public Document includeSignature(Document doc) throws Exception {
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        WSEncryptionPart timestampPart = new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "");
        WSEncryptionPart bodyPart = new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace, "Content");
        WSEncryptionPart[] parts = new WSEncryptionPart[]{timestampPart, bodyPart};
        return includeSignature(doc, true, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                WSConstants.C14N_EXCL_OMIT_COMMENTS, WSConstants.SHA256, parts, WSConstants.ISSUER_SERIAL);
    }

    private Document includeSignature(Document doc, boolean includeKeyInfo, String sigAlgorithm,
                                      String canonAlgo, String digestAlgo, WSEncryptionPart[] parts,
                                      int keyIdentifierType) throws Exception {
        WSSecHeader secHeader = new WSSecHeader(doc);
        if (secHeader.isEmpty()) {
            secHeader.insertSecurityHeader();
        }
        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo(keyAlias, "byx");
        builder.setKeyIdentifierType(keyIdentifierType);
        builder.setSignatureAlgorithm(sigAlgorithm);
        builder.setSigCanonicalization(canonAlgo);
        builder.setDigestAlgo(digestAlgo);
        if (parts != null) {
            for (WSEncryptionPart part : parts) {
                builder.getParts().add(part);
            }
        }
        // Replace the null parameters with actual values if needed
        // Use the properties and crypto instance configured in the init() method
        //new WSSecSignature(doc, crypto, null, null,
        //        keyAlias, null, includeKeyInfo, sigAlgorithm, canonAlgo, digestAlgo, parts, keyIdentifierType);
        return builder.build(crypto);
    }
}

