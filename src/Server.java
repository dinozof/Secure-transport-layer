import it.unipr.netsec.util.ByteUtils;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;


/**
 * ASSEGNAMENTO NUMERO 1
 * NOME: VOLPONI STEFANO
 * MATRICOLA: 279281
 */

public class Server {
    //private static final String key="0123456789abcdef";
    public static void main(String[] args) throws Exception {


        while (true) {
            int PORT = 4000;
            byte[] buf = new byte[4096];
            byte[] buf2 = new byte[4096];
            SecureDatagramSocket sk = new SecureDatagramSocket(null, 4000);

            System.out.println("GETTIG READY FOR A NEW SESSION");
            /**
             * DIFFIE HELLMAN HANDSHAKE
             * */
            DiffieHellman DH = new DiffieHellman();

            //GENERATE G & P
            DHParameterSpec dh_param_spec;
            dh_param_spec = DH.generateDhParamenters(512);
            BigInteger p = dh_param_spec.getP();
            BigInteger g = dh_param_spec.getG();

            System.out.println("p: " + p.toString(16));
            System.out.println("g: " + g.toString(16));

            //GENERATE XS
            KeyPair key_pair_s;
            BigInteger xs;
            key_pair_s = DH.generateDhKeyPair(dh_param_spec);
            xs = ((DHPrivateKey) key_pair_s.getPrivate()).getX();
            System.out.println("xs: " + xs.toString(16));


            System.out.println("Server started");


            //WAIT FOR A CLIENT
            DatagramPacket dgp = new DatagramPacket(buf, buf.length);
            System.out.println("Waiting for messages...");
            sk.receive(dgp);
            String rcvd = new String(dgp.getData(), 0, dgp.getLength()) + ", from address: "
                    + dgp.getAddress() + ", port: " + dgp.getPort();
            System.out.println(rcvd);

            // SENDING P
            buf = p.toByteArray();
            System.out.println("SENDING P");
            DatagramPacket out = new DatagramPacket(buf, buf.length, dgp.getAddress(), dgp.getPort());
            sk.send(out);

            Arrays.fill(buf, (byte) 0);
            out = new DatagramPacket(buf, buf.length, dgp.getAddress(), dgp.getPort());


            //SENDING G
            buf = g.toByteArray();
            System.out.println("SENDING G");
            out.setData(buf);
            out.setLength(buf.length);
            sk.send(out);

            Arrays.fill(buf, (byte) 0);
            out = new DatagramPacket(buf, buf.length, dgp.getAddress(), dgp.getPort());

            //SENDING PUBLIC
            BigInteger ys;
            ys = ((DHPublicKey) key_pair_s.getPublic()).getY();
            System.out.println("YS: " + ys.toString(16));
            buf = ys.toByteArray();
            System.out.println("SENDING PUBLIC");
            out.setData(buf);
            out.setLength(buf.length);
            sk.send(out);

            buf = new byte[4096];
            dgp = new DatagramPacket(buf, buf.length);

            //GETTING CLIENT PUBLIC KEY
            sk.receive(dgp);
            rcvd = "rcvd from " + dgp.getAddress() + ", " + dgp.getPort();
            System.out.println(rcvd);

            //BUILDING CLIENT PUBLIC KEY
            BigInteger yc = new BigInteger(dgp.getData());
            System.out.println("YC: " + yc.toString(16));
            DHPublicKeySpec dhspec = new DHPublicKeySpec(yc, p, g);
            KeyFactory keyFact = KeyFactory.getInstance("DH");
            PublicKey pubKey = keyFact.generatePublic(dhspec);
            //System.out.println(pubKey.toString());

            //GENERATING SHARED KEY
            byte[] ka_bytes = DH.computeDhSecret(key_pair_s, pubKey);
            System.out.println("Ka: " + ByteUtils.bytesToHexString(ka_bytes));
            System.out.println("SIZE: " + ka_bytes.length);

            /**
             *  FINE DIFFIE HELLMAN HANDSHAKE
             * */

            //SHA -> 64 -> 256
            String algo = "sha-256";
            MessageDigest md = MessageDigest.getInstance(algo);
            byte[] hash = md.digest(ka_bytes);

            //SETTING KEY FOR ENCRYPTED COMMUNICATION
            sk.setkey(hash);

            while (true) {

                DatagramPacket pkt = new DatagramPacket(buf2, buf2.length);
                sk.receive(pkt);
                if(new String(pkt.getData()).equals(".bye")) {
                    System.out.println("USER CLOSED CONNECTION");
                    break;
                }
                String rec = new String(pkt.getData(), 0, pkt.getLength()) + ", from address: "
                        + pkt.getAddress() + ", port: " + pkt.getPort();
                System.out.println(rec);

                System.out.print("\n\nTYPE SOMETHING:   \n\n");
                BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
                String outMessage = stdin.readLine();

                buf = outMessage.getBytes();

                pkt.setData(buf);
                pkt.setLength(buf.length);
                sk.send(pkt);
                System.out.println("MESSAGE SENT");

            }
            sk.close();
        }
    }
}
