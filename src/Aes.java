import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import it.unipr.netsec.util.ByteUtils;
import sun.misc.*;



public class Aes {



    private static final String ALGO = "AES/CBC/PKCS5Padding";
    private  final byte[] keyValue;
    private final byte[] iv= ByteUtils.hexStringToBytes("11223344556677881122334455667788");
    private  static final boolean verbose=true; //set to FALSE to disable comment


    public  Aes(byte[] nkey){
        keyValue=nkey;
    }

    public  byte[] encrypt(byte[] data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        IvParameterSpec iv_spec=(iv!=null)? new IvParameterSpec(iv) : null;
        c.init(Cipher.ENCRYPT_MODE, key,iv_spec);
        byte[] encVal = c.doFinal(data);
        if(verbose){
            System.out.println("\n\n");
            for (int i=0; i<10; i++){
                System.out.print("==");
            }

            System.out.println("\n");
            System.out.println("BEGINNING ENCRYPTION");
            System.out.println("text: "+new String(data));
            System.out.println("plaintext: "+ByteUtils.bytesToHexString(data)+" ("+data.length+" bytes)");
            System.out.println("key: "+ByteUtils.bytesToHexString(keyValue));
            System.out.println("iv: "+(iv!=null? ByteUtils.bytesToHexString(iv) : "none"));
            System.out.println("ciphertext: "+ByteUtils.bytesToHexString(encVal)+" ("+encVal.length+" bytes)");
            System.out.println("\n");
            for (int i=0; i<10; i++){
                System.out.print("==");
            }
            System.out.println("\n\n");
        }
        return encVal;
    }

    public  byte[] decrypt(byte[] encryptedData) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        IvParameterSpec iv_spec=(iv!=null)? new IvParameterSpec(iv) : null;
        c.init(Cipher.DECRYPT_MODE, key,iv_spec);
        byte[] decValue = c.doFinal(encryptedData);
        if(verbose) {
            System.out.println("\n\n");
            for (int i = 0; i < 10; i++) {
                System.out.print("==");
            }
            System.out.println("\n");
            System.out.println("BEGINNING DECRYPTION");
            System.out.println("ciphertext: " + ByteUtils.bytesToHexString(encryptedData) + " (" + encryptedData.length + " bytes)");
            System.out.println("iv: " + (iv != null ? ByteUtils.bytesToHexString(iv) : "none"));
            System.out.println("key: " + ByteUtils.bytesToHexString(keyValue));
            System.out.println("plaintext: "+ByteUtils.bytesToHexString(decValue)+" ("+decValue.length+" bytes)");
            System.out.println("text: "+new String(decValue));
            System.out.println("\n");
            for (int i=0; i<10; i++){
                System.out.print("==");
            }
            System.out.println("\n\n");
        }
        return decValue;
    }

    private  Key generateKey() throws Exception {
        String key_algo=ALGO.substring(0,ALGO.indexOf('/'));
        Key key = new SecretKeySpec(keyValue, key_algo);
        return key;
    }

}