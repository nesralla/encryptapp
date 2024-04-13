package com.byx.encryptapp.services;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.callback.DOMCallbackLookup;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.processor.Processor;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.springframework.beans.factory.annotation.Value;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

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
            data.setCallbackHandler(new AtlanteWsClientCallbackHandler());
            Element securityHeader = WSSecurityUtil.getSecurityHeader(doc, "");
            NodeList encryptedKeyNodeList = securityHeader.getElementsByTagNameNS(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN);
            int encryptedKeyCount = encryptedKeyNodeList.getLength();
            if (encryptedKeyCount != 1) {
// deve ter ao menos e somente 1 encryptedKey
                throw new Exception("deve ter ao menos e somente 1 encryptedKey");
            }
            Node encryptedKeyNode = encryptedKeyNodeList.item(0);
            if (!(encryptedKeyNode instanceof Element)) {
// o node do encryptedKey deve ser um elemento
                throw new Exception("o node do encryptedKey deve ser um elemento");
            }
            Element encryptedKeyElement = (Element) encryptedKeyNode;
            Processor p = cfg.getProcessor(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
            WSDocInfo wsDocInfo = new WSDocInfo(securityHeader.getOwnerDocument());
            wsDocInfo.setCallbackLookup(new DOMCallbackLookup(securityHeader.getOwnerDocument()));
            wsDocInfo.setCrypto(crypto);
            wsDocInfo.setSecurityHeader(securityHeader);
            List<WSSecurityEngineResult> results = p.handleToken(encryptedKeyElement, data, wsDocInfo);
            results.getFirst();
//TODO testar XPATH
            encryptedKeyElement.getParentNode().removeChild(encryptedKeyElement);
            Document cleanedDoc = removeSecurityHeaderIfEmpty(doc);
            return cleanedDoc;
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    public static Document removeSignature(Document docToVerify) throws Exception, WSSecurityException {
        try {
            Document doc = (Document) docToVerify.cloneNode(true);
            WSSConfig cfg = WSSConfig.getNewInstance();
            RequestData data = new RequestData();
            data.setActor("");
            data.setWssConfig(cfg);
            data.setDecCrypto(crypto);
            data.setSigVerCrypto(crypto);
            data.setCallbackHandler(new AtlanteWsClientCallbackHandler());
            Element securityHeader = WSSecurityUtil.getSecurityHeader(doc, "");
            NodeList signatureNodeList = securityHeader.getElementsByTagNameNS(WSConstants.SIG_NS, WSConstants.SIG_LN);
            int signatureCount = signatureNodeList.getLength();
            if (signatureCount != 1) {
// deve ter ao menos e somente 1 signature
                throw new Exception("deve ter ao menos e somente 1 signature");
            }
            Node signatureNode = signatureNodeList.item(0);
            if (!(signatureNode instanceof Element)) {
// o node do signature deve ser um elemento
                throw new Exception("o node do signature deve ser um elemento");
            }
            Element signatureElement = (Element) signatureNode;
            Processor p = cfg.getProcessor(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
            WSDocInfo wsDocInfo = new WSDocInfo(securityHeader.getOwnerDocument());
            wsDocInfo.setCallbackLookup(new DOMCallbackLookup(securityHeader.getOwnerDocument()));
            wsDocInfo.setCrypto(crypto);
            wsDocInfo.setSecurityHeader(securityHeader);
            List<WSSecurityEngineResult> results = p.handleToken(signatureElement, data, wsDocInfo);
            WSSecurityEngineResult signatureResult = (WSSecurityEngineResult) results.get(0);
            List<WSDataRef> sigDataRefs = (List<WSDataRef>) signatureResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
            if (sigDataRefs.size() != 3) {
// deve ter duas assinaturas (timestamp e body e confirmation)
                throw new Exception("deve ter três assinaturas (timestamp e body e confirmation)");
            }
            String localName1 = sigDataRefs.get(0).getName().getLocalPart();
            String localName2 = sigDataRefs.get(1).getName().getLocalPart();
            String localName3 = sigDataRefs.get(2).getName().getLocalPart();
            if (!((WSConstants.TIMESTAMP_TOKEN_LN.equals(localName1) || WSConstants.TIMESTAMP_TOKEN_LN.equals(localName2) || WSConstants.TIMESTAMP_TOKEN_LN.equals(localName3))
                    && (WSConstants.ELEM_BODY.equals(localName1) || WSConstants.ELEM_BODY.equals(localName2) || WSConstants.ELEM_BODY.equals(localName3))
                    && (WSConstants.SIGNATURE_CONFIRMATION_LN.equals(localName1) || WSConstants.SIGNATURE_CONFIRMATION_LN.equals(localName2) || WSConstants.SIGNATURE_CONFIRMATION_LN.equals(localName3)))) {
                throw new Exception("deve ter três assinaturas (timestamp e body e confirmation)");
            }
            if (!(("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".equals(sigDataRefs.get(0).getAlgorithm()))
                    || ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".equals(sigDataRefs.get(1).getAlgorithm()))
                    || ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".equals(sigDataRefs.get(2).getAlgorithm())))) {
                throw new Exception("deve ser rsa-sha256");
            }
            if (!((WSConstants.SHA256.equals(sigDataRefs.get(0).getDigestAlgorithm()))
                    || (WSConstants.SHA256.equals(sigDataRefs.get(1).getDigestAlgorithm()))
                    || (WSConstants.SHA256.equals(sigDataRefs.get(2).getDigestAlgorithm())))) {
                throw new Exception("deve ser sha256");
            }
//TODO testar XPATH
            signatureElement.getParentNode().removeChild(signatureElement);
            Document cleanedDoc = removeSecurityHeaderIfEmpty(doc);
            return cleanedDoc;
        } catch (WSSecurityException e) {
            throw new Exception(e);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }
}
