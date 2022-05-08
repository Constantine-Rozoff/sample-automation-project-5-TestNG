package net.absoft.data;

import java.util.Objects;

public class Response {
    private int code;
    private String message;

    public int getCode() { return code; }

    public String getMessage() { return message; }

    public Response(int code, String message) {
        this.code = code;
        this.message = message;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Response response = (Response) o;
        return code == response.code && Objects.equals(message, response.message);
    }

    @Override
    public int hashCode() { return Objects.hash(code, message); }

    @Override
    public String toString() {
        return "Response{" +
                "code=" + code +
                ", message='" + message + '\'' +
                '}';
    }
}
