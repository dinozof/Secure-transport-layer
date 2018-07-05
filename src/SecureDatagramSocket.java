import it.unipr.netsec.util.ByteUtils;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.Arrays;

/**
 * Created by stefano on 05/05/17.
 */
public class SecureDatagramSocket extends DatagramSocket {

    private Aes aes;
    private byte[] key=null;

    public SecureDatagramSocket(byte[] secureKey) throws SocketException {
        super();
        key=secureKey;
    }

    public SecureDatagramSocket(byte[] secureKey, int i) throws SocketException {
        super(i);
        key=secureKey;
    }


    public void setkey(byte[] securekey){
        key=securekey;
    }

    @Override
    public void send(DatagramPacket p) throws IOException {

        if(key!=null){
            try {
                byte[] encrypted;
                byte[] toSend=p.getData();
                aes = new Aes(key);
                encrypted =aes.encrypt(toSend);
                p.setData(encrypted);
                super.send(p);
            } catch (Exception e) {
                e.printStackTrace();
            }

        }else{
            super.send(p);
        }


    }

    @Override
    public void receive(DatagramPacket p) throws IOException {
        super.receive(p);
        if(key!=null) {
            byte[] pData = p.getData();
            byte[] encrypted = trim(pData);
            try {
                aes = new Aes(key);

                byte[] plainText = aes.decrypt(encrypted);

                p.setData(plainText);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        p.setData(trim(p.getData()));

    }


    static byte[] trim(byte[] bytes)
    {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)
        {
            --i;
        }

        return Arrays.copyOf(bytes, i + 1);
    }


}
