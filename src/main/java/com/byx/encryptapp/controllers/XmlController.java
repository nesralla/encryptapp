package com.byx.encryptapp.controllers;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/xml")
public class XmlController {
    @PostMapping("/encrypt")
    public String encryptXml(@RequestBody String xml) {
        // Lógica para criptografar o XML com a chave


        return "XML criptografado";
    }

    @PostMapping("/decrypt")
    public String decryptXml(@RequestBody String encryptedXml) {
        // Lógica para descriptografar o XML com a chave
        return "XML descriptografado";
    }
}
