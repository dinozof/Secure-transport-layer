import it.unipr.netsec.util.ByteUtils;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;

/**
 * ASSEGNAMENTO NUMERO 1
 * NOME: VOLPONI STEFANO
 * MATRICOLA: 279281
 * NOTA: per disabilitare la stampa della funzione di criptazione AES, settare il parametro
 * "verbose" a FALSE nella medesima classe.
 */

public class Client {
    //private static final String key="0123456789abcdef";

    public static void main(String[] args) throws Exception {



        SecureDatagramSocket s = new SecureDatagramSocket(null);
        byte[] buf = new byte[4096];
        byte[] buf2 = new byte[4096];
        byte[] buf3 = new byte[4096];



        DiffieHellman DH = new DiffieHellman();
        DHParameterSpec dh_param_spec;
        BigInteger p;
        BigInteger g;


        InetAddress hostAddress = InetAddress.getByName("localhost");

        //CONNECT WITH THE SERVER
        System.out.println("\nCONNECTING WITH THE SERVER");
        String outMessage = "Hi!";

        buf = outMessage.getBytes();

        DatagramPacket out = new DatagramPacket(buf, buf.length, hostAddress, 4000);
        s.send(out);

        buf = new byte[4096];
        DatagramPacket dp = new DatagramPacket(buf, buf.length);
        DatagramPacket dp2 = new DatagramPacket(buf2, buf2.length);
        DatagramPacket dp3 = new DatagramPacket(buf3, buf3.length);

        /**
         * DIFFIE HELLMAN HANDSHAKE
         * */

        // RECEIVE P
        s.receive(dp);
        String rcvd = "rcvd from " + dp.getAddress() + ", " + dp.getPort();
        System.out.println(rcvd);

        p=new BigInteger(dp.getData());
        System.out.println("p: "+p.toString(16));


        // RECEIVE G
        s.receive(dp2);
        rcvd = "rcvd from " + dp2.getAddress() + ", " + dp2.getPort();
        System.out.println(rcvd);

        g=new BigInteger(dp2.getData());
        System.out.println("g: "+g.toString(16));

        //GENERATE XC
        dh_param_spec=new DHParameterSpec(p,g);
        KeyPair key_pair_c;
        BigInteger xc;
        key_pair_c=DH.generateDhKeyPair(dh_param_spec);
        xc=((DHPrivateKey)key_pair_c.getPrivate()).getX();
        System.out.println("xc: "+xc.toString(16));

        s.receive(dp3);
        rcvd = "rcvd from " + dp3.getAddress() + ", " + dp3.getPort();
        System.out.println(rcvd);

        // GET SERVER PUBLIC
        BigInteger ys = new BigInteger(dp3.getData());
        System.out.println("YS: "+ys.toString(16));
        DHPublicKeySpec dhspec=new DHPublicKeySpec(ys,p,g);
        KeyFactory keyFact = KeyFactory.getInstance("DH");
        PublicKey pubKey = keyFact.generatePublic(dhspec);
        //System.out.println(pubKey.toString());


        //GENRATE SHARED KEY
        byte[] ka_bytes=DH.computeDhSecret(key_pair_c,pubKey);
        System.out.println("Ka: "+ ByteUtils.bytesToHexString(ka_bytes));
        System.out.println("SIZE: "+ka_bytes.length);

        //SEND CLIENT PUBLIC KEY
        BigInteger yc;
        yc=((DHPublicKey)key_pair_c.getPublic()).getY();
        System.out.println("SENDING PUBLIC");
        System.out.println("YC: "+yc.toString(16));


        buf = new byte[4096];
        out = new DatagramPacket(buf, buf.length, hostAddress, 4000);
        buf=yc.toByteArray();
        out.setData(buf);
        out.setLength(buf.length);
        s.send(out);

        //SHA -> 64 -> 256
        String algo="sha-256";
        MessageDigest md=MessageDigest.getInstance(algo);
        byte[] hash=md.digest(ka_bytes);

        System.out.println("HASH: "+ByteUtils.bytesToHexString(hash)+" SIZE: "+ ByteUtils.bytesToHexString(hash).length());

        /**
         * END DIFFIE HELLMAN HANDSHAKE
         * */

        s.setkey(hash);

        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));



        while (true) {

            System.out.print("\n\nTYPE SOMETHING:   \n\n");
            outMessage = stdin.readLine();


            buf = outMessage.getBytes();
            out.setData(buf);
            out.setLength(buf.length);
            s.send(out);
            if (outMessage.equals(".bye"))
                break;
            buf = new byte[4096];
            dp = new DatagramPacket(buf, buf.length);

            s.receive(dp);
            rcvd = "rcvd from " + dp.getAddress() + ", " + dp.getPort() + ": "
                    + new String(dp.getData(), 0, dp.getLength());
            System.out.println(rcvd);
        }
        s.close();
        System.exit(0);
    }
}