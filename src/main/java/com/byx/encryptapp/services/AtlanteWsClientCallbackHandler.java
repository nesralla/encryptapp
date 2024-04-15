package com.byx.encryptapp.services;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

public class AtlanteWsClientCallbackHandler implements CallbackHandler {
    private final String password;

    /**
     * Construtor que recebe a senha que será utilizada nos callbacks.
     *
     * @param password A senha para acesso às chaves criptográficas
     */
    public AtlanteWsClientCallbackHandler(String password) {
        this.password = password;
    }

    /**
     * Manipula os callbacks relacionados à segurança.
     *
     * @param callbacks Array de Callbacks que podem incluir PasswordCallbacks.
     */
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback passwordCallback) {
                // Define a senha no callback para ser usada pelo processo de segurança.
                passwordCallback.setPassword(password.toCharArray());
            } else {
                throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
            }
        }
    }
}
