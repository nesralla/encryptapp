package com.byx.encryptapp.services;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException.ErrorCode;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.callback.DOMCallbackLookup;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.processor.Processor;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.xml.security.signature.InvalidSignatureValueException;
import org.springframework.beans.factory.annotation.Value;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import javax.xml.namespace.QName;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import java.util.List;

public class DecryptDocService {
    @Value("${signature.key.alias}")
    private String keyAlias;

    private static Crypto crypto;
    public DecryptDocService() throws Exception {
        // Initialize WSSConfig to ensure the correct operation
        WSSConfig.init();
        // Initialize the crypto instance with the necessary properties
        // Replace the null parameters with actual values
        crypto =  CryptoFactory.getInstance("wss40.properties");
    }
    public static Document removeEncryption(Document docToVerify) throws Exception, WSSecurityException {
        try {
            Document doc = (Document) docToVerify.cloneNode(true);
            WSSConfig cfg = WSSConfig.getNewInstance();
            RequestData data = new RequestData();
            data.setActor("");
            data.setWssConfig(cfg);
            data.setDecCrypto(crypto);
            data.setSigVerCrypto(crypto);
            data.setCallbackHandler(new AtlanteWsClientCallbackHandler(""));
            Element securityHeader = WSSecurityUtil.getSecurityHeader(doc, "");
            NodeList encryptedKeyNodeList = securityHeader.getElementsByTagNameNS(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN);
            int encryptedKeyCount = encryptedKeyNodeList.getLength();
            if (encryptedKeyCount != 1) {
// deve ter ao menos e somente 1 encryptedKey
                throw new Exception("deve ter ao menos e somente 1 encryptedKey");
            }
            Node encryptedKeyNode = encryptedKeyNodeList.item(0);
            if (!(encryptedKeyNode instanceof Element encryptedKeyElement)) {
// o node do encryptedKey deve ser um elemento
                throw new Exception("o node do encryptedKey deve ser um elemento");
            }
            Processor p = cfg.getProcessor(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
            WSDocInfo wsDocInfo = new WSDocInfo(securityHeader.getOwnerDocument());
            wsDocInfo.setCallbackLookup(new DOMCallbackLookup(securityHeader.getOwnerDocument()));
            wsDocInfo.setCrypto(crypto);
            wsDocInfo.setSecurityHeader(securityHeader);
            List<WSSecurityEngineResult> results = p.handleToken(encryptedKeyElement, data);
            //TODO testar XPATH
            encryptedKeyElement.getParentNode().removeChild(encryptedKeyElement);
            return removeSecurityHeaderIfEmpty(doc);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }
    /**
     * Removes the security header from the document if it is empty.
     *
     * @param doc The document from which the security header might be removed.
     * @return The possibly modified document.
     */
    public static Document removeSecurityHeaderIfEmpty(Document doc) {
        Element securityHeader = getSecurityHeader(doc);
        if (securityHeader != null && !hasChildElements(securityHeader)) {
            // If the security header exists and has no child elements, remove it.
            securityHeader.getParentNode().removeChild(securityHeader);
        }
        return doc;
    }

    /**
     * Retrieves the security header element from the document.
     *
     * @param doc The document from which to retrieve the security header.
     * @return The security header element, or null if not found.
     */
    private static Element getSecurityHeader(Document doc) {
        return (Element) doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security").item(0);
    }

    /**
     * Checks if an element has any child elements.
     *
     * @param element The element to check.
     * @return true if the element has no child elements, false otherwise.
     */
    private static boolean hasChildElements(Element element) {
        return element != null && element.getChildNodes().getLength() == 0;
    }
}
