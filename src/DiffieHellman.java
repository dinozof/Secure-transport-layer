import it.unipr.netsec.util.ByteUtils;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;


public class DiffieHellman {

	/** The 1024-bit Diffie-Hellman modulus values used by SKIP */
	private static final byte[] MODULUS={
		(byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
		(byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
		(byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
		(byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
		(byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
		(byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
		(byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
		(byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
		(byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
		(byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
		(byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
		(byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
		(byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
		(byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
		(byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
		(byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
		(byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
		(byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
		(byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
		(byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
		(byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
		(byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
		(byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
		(byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
		(byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
		(byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
		(byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
		(byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
		(byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
		(byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
		(byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
		(byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
    };

	/** The base value used with the 1024-bit SKIP modulus */
	private static final long BASE=2;
	
	
	
	/** Generates DH parameters.
	 * @param k_len the key size
	 * @return DHParameterSpec with the DH parameters <i>g</i> and <i>p</i>
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidParameterSpecException */
	public  DHParameterSpec generateDhParamenters(int k_len) throws NoSuchAlgorithmException, InvalidParameterSpecException {
		System.out.print("Creating Diffie-Hellman parameters...");
		AlgorithmParameterGenerator dh_param_gen=AlgorithmParameterGenerator.getInstance("DH");
		//dh_param_gen.init(new DHGenParameterSpec(k_len,8));
		dh_param_gen.init(k_len);
		DHParameterSpec dh_param_spec=(DHParameterSpec)dh_param_gen.generateParameters().getParameterSpec(DHParameterSpec.class);	
		System.out.println(" done.");
		return dh_param_spec;
	}

	
	/** Generates DH public/private keys.
	 * @param dh_param_spec DH <i>g</i> and <i>p</i> parameters
	 * @return the DH public/private key pair 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException */
	public  KeyPair generateDhKeyPair(DHParameterSpec dh_param_spec) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator key_pair_gen=KeyPairGenerator.getInstance("DH");
		key_pair_gen.initialize(dh_param_spec);
		System.out.print("Generating DH keypair...");
		KeyPair key_pair=key_pair_gen.generateKeyPair();
		System.out.println(" done.");
		return key_pair;
	}

	
	/** Gets DH public/private keys.
	 * @param dh_param_spec DH <i>g</i> and <i>p</i> parameters
	 * @param x DH private key
	 * @return the DH public/private key pair 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException */
	public  KeyPair getDhKeyPair(DHParameterSpec dh_param_spec, BigInteger x) throws NoSuchAlgorithmException, InvalidKeySpecException {
		BigInteger g=dh_param_spec.getG();
		BigInteger p=dh_param_spec.getP();
		BigInteger y=g.modPow(x,p);
		KeyFactory dh_key_factory=KeyFactory.getInstance("DH");
		KeyPair key_pair=new KeyPair(dh_key_factory.generatePublic(new DHPublicKeySpec(y,p,g)),dh_key_factory.generatePrivate(new DHPrivateKeySpec(x,p,g)));
		return key_pair;
	}

	
	/** Computes the DH secret.
	 * @param key_pair local DH public/private key pair
	 * @param y remote DH public key
	 * @return the DH secret 
	 * @throws InvalidKeyException 
	 * @throws NoSuchAlgorithmException */
	public  byte[] computeDhSecret(KeyPair key_pair, PublicKey y) throws InvalidKeyException, NoSuchAlgorithmException {
		KeyAgreement key_agree=KeyAgreement.getInstance("DH");		
		key_agree.init(key_pair.getPrivate());
		key_agree.doPhase(y,true);
		return key_agree.generateSecret();
	}


}
