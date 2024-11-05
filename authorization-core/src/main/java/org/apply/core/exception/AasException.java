package org.apply.core.exception;

public class AasException extends RuntimeException {

    private final int code;

    public AasException(int code, String msg) {
        super(msg);
        this.code = code;
    }

    public AasException(int code, String msg, Throwable cause) {
        super(msg, cause);
        this.code = code;
    }
}
