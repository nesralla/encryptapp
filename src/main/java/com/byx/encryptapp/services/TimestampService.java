package com.byx.encryptapp.services;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.callback.DOMCallbackLookup;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.processor.Processor;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;
import javax.xml.namespace.QName;

import java.util.List;

import static org.apache.wss4j.common.crypto.CryptoFactory.getInstance;

@Component
public class TimestampService {
    @Value("${signature.key.alias}")
    private String keyAlias;

    private static Crypto crypto = null;

    public TimestampService() throws Exception {
        // Initialize WSSConfig to ensure the correct operation
        WSSConfig.init();
        // Initialize the crypto instance with the necessary properties
        // Replace the null parameters with actual values
        crypto =  getInstance("wss40.properties");
    }
    public Document includeTimestamp(Document doc) throws Exception {
        return includeTimestamp(doc, 300);
    }

    public Document includeTimestamp(Document doc, Integer timeInSeconds) throws Exception {

        WSSecHeader secHeader = new WSSecHeader(doc);
        if (secHeader.isEmpty()) {
            secHeader.insertSecurityHeader();
        }

        WSSecTimestamp builder = new WSSecTimestamp(secHeader);
        builder.setTimeToLive(timeInSeconds);

        return builder.build();
    }
    public Document removeTimestamp(Document docToVerify) throws InvalidTimestampException{
        try {
            Document doc = (Document) docToVerify.cloneNode(true);
            Element securityHeader = WSSecurityUtil.getSecurityHeader(doc, "");
            NodeList timestampNodeList = securityHeader.getElementsByTagNameNS(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN);
            int timestampCount = timestampNodeList.getLength();
            if (timestampCount != 1) {
                throw new InvalidTimestampException("Deve ter ao menos e somente 1 timestamp");
            }
            Node timestampNode = timestampNodeList.item(0);
            if (!(timestampNode instanceof Element timestampElement)) {
                throw new InvalidTimestampException("O node do timestamp deve ser um elemento");
            }
            RequestData data = new RequestData();
            data.setActor("");
            data.setWssConfig(WSSConfig.getNewInstance());
            data.setDecCrypto(crypto);
            data.setSigVerCrypto(crypto);
            data.setCallbackHandler(new AtlanteWsClientCallbackHandler(""));
            Processor processor = data.getWssConfig().getProcessor(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
            WSDocInfo wsDocInfo = new WSDocInfo(doc);
            wsDocInfo.setCallbackLookup(new DOMCallbackLookup(doc));
            wsDocInfo.setCrypto(crypto);
            wsDocInfo.setSecurityHeader(securityHeader);
            List<WSSecurityEngineResult> results = processor.handleToken(timestampElement, data);
            timestampNode.getParentNode().removeChild(timestampNode);
            return removeSecurityHeaderIfEmpty(doc);
        } catch (XMLSecurityException e) {
            throw new InvalidTimestampException(e.getMessage(), e);
        }
    }

    private Document removeSecurityHeaderIfEmpty(Document doc) {
        // Implementar lógica para remover cabeçalho de segurança se estiver vazio
        return doc;
    }


}
