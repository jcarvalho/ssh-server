package pt.jcarvalho.ssh;

import java.io.Closeable;
import java.io.IOException;

public interface SecureChannel extends Closeable {

    public String setup() throws IOException;

    public String readLine() throws IOException;

    public void write(String string) throws IOException;

    public void close(int code) throws IOException;

}
