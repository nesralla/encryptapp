package com.byx.encryptapp.services;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
@Component
public class TimestampService {

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
}

