package com.galitianu.keycloak.exceptions;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class FirebaseScryptRuntimeException extends RuntimeException {
    public FirebaseScryptRuntimeException() {
    }

    public FirebaseScryptRuntimeException(String message) {
        super(message);
    }

    public FirebaseScryptRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public FirebaseScryptRuntimeException(Throwable cause) {
        super(cause);
    }

    public FirebaseScryptRuntimeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
