package com.byx.encryptapp.services;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.callback.DOMCallbackLookup;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.processor.Processor;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.signature.InvalidSignatureValueException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import java.util.List;

import static org.apache.wss4j.common.crypto.CryptoFactory.*;


@Component
public class SignatureService {

    @Value("${signature.key.alias}")
    private String keyAlias;

    private static Crypto crypto = null;

    public SignatureService() throws Exception {
        // Initialize WSSConfig to ensure the correct operation
        WSSConfig.init();
        // Initialize the crypto instance with the necessary properties
        // Replace the null parameters with actual values
        crypto =  getInstance("wss40.properties");
    }

    public Document includeSignature(Document doc) throws Exception {
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        WSEncryptionPart timestampPart = new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "");
        WSEncryptionPart bodyPart = new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace, "Content");
        WSEncryptionPart[] parts = new WSEncryptionPart[]{timestampPart, bodyPart};
        return includeSignature(doc,
                parts);
    }

    private Document includeSignature(Document doc,
                                      WSEncryptionPart[] parts) throws Exception {
        WSSecHeader secHeader = new WSSecHeader(doc);
        if (secHeader.isEmpty()) {
            secHeader.insertSecurityHeader();
        }
        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo(keyAlias, "byx");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        builder.setSigCanonicalization(org.apache.wss4j.common.WSS4JConstants.C14N_EXCL_OMIT_COMMENTS);
        builder.setDigestAlgo(org.apache.wss4j.common.WSS4JConstants.SHA256);
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


    public static Document removeSignature(Document docToVerify) throws InvalidSignatureValueException {
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
            NodeList signatureNodeList = securityHeader.getElementsByTagNameNS(WSConstants.SIG_NS, WSConstants.SIG_LN);
            int signatureCount = signatureNodeList.getLength();
            if (signatureCount != 1) {
// deve ter ao menos e somente 1 signature
                throw new InvalidSignatureValueException("deve ter ao menos e somente 1 signature");
            }
            Node signatureNode = signatureNodeList.item(0);
            if (!(signatureNode instanceof Element signatureElement)) {
// o node do signature deve ser um elemento
                throw new InvalidSignatureValueException("o node do signature deve ser um elemento");
            }
            Processor p = cfg.getProcessor(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
            WSDocInfo wsDocInfo = new WSDocInfo(securityHeader.getOwnerDocument());
            wsDocInfo.setCallbackLookup(new DOMCallbackLookup(securityHeader.getOwnerDocument()));
            wsDocInfo.setCrypto(crypto);
            wsDocInfo.setSecurityHeader(securityHeader);
            List<WSSecurityEngineResult> results = p.handleToken(signatureElement, data);
            WSSecurityEngineResult signatureResult = (WSSecurityEngineResult) results.get(0);
            List<WSDataRef> sigDataRefs = (List<WSDataRef>) signatureResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
            if (sigDataRefs.size() != 3) {
// deve ter duas assinaturas (timestamp e body e confirmation)
                throw new InvalidSignatureValueException("deve ter três assinaturas (timestamp e body e confirmation)");
            }
            String localName1 = sigDataRefs.get(0).getName().getLocalPart();
            String localName2 = sigDataRefs.get(1).getName().getLocalPart();
            String localName3 = sigDataRefs.get(2).getName().getLocalPart();
            if (!((WSConstants.TIMESTAMP_TOKEN_LN.equals(localName1) || WSConstants.TIMESTAMP_TOKEN_LN.equals(localName2) || WSConstants.TIMESTAMP_TOKEN_LN.equals(localName3))
                    && (WSConstants.ELEM_BODY.equals(localName1) || WSConstants.ELEM_BODY.equals(localName2) || WSConstants.ELEM_BODY.equals(localName3))
                    && (WSConstants.SIGNATURE_CONFIRMATION_LN.equals(localName1) || WSConstants.SIGNATURE_CONFIRMATION_LN.equals(localName2) || WSConstants.SIGNATURE_CONFIRMATION_LN.equals(localName3)))) {
                throw new InvalidSignatureValueException("deve ter três assinaturas (timestamp e body e confirmation)");
            }
            if (!(("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".equals(sigDataRefs.get(0).getAlgorithm()))
                    || ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".equals(sigDataRefs.get(1).getAlgorithm()))
                    || ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".equals(sigDataRefs.get(2).getAlgorithm())))) {
                throw new InvalidSignatureValueException("deve ser rsa-sha256");
            }
            if (!((WSConstants.SHA256.equals(sigDataRefs.get(0).getDigestAlgorithm()))
                    || (WSConstants.SHA256.equals(sigDataRefs.get(1).getDigestAlgorithm()))
                    || (WSConstants.SHA256.equals(sigDataRefs.get(2).getDigestAlgorithm())))) {
                throw new InvalidSignatureValueException("deve ser sha256");
            }
//TODO testar XPATH
            signatureElement.getParentNode().removeChild(signatureElement);
            return removeSecurityHeaderIfEmpty(doc);
        } catch (WSSecurityException | InvalidSignatureValueException e) {
            throw new InvalidSignatureValueException();
        }
    }
    public static Document removeSecurityHeaderIfEmpty(Document doc) {
        Element securityHeader = getSecurityHeader(doc);
        if (securityHeader != null && !hasChildElements(securityHeader)) {
            // If the security header exists and has no child elements, remove it.
            securityHeader.getParentNode().removeChild(securityHeader);
        }
        return doc;
    }
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

