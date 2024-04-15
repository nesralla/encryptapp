package com.byx.encryptapp.services;

public class InvalidTimestampException extends Exception {
    public InvalidTimestampException(String message) {
        super(message);
    }

    public InvalidTimestampException(String message, Throwable cause) {
        super(message, cause);
    }
}
