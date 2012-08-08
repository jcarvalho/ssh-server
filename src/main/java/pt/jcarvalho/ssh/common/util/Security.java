package pt.jcarvalho.ssh.common.util;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

public class Security {

	public static RSAPublicKey rsaPub;
	public static RSAPrivateKey rsaPriv;
	public static KeyPair pair;

	public static RSAPublicKey getRsaPub() {
		return rsaPub;
	}

	public static void setRsaPub(RSAPublicKey rsaPub) {
		Security.rsaPub = rsaPub;
	}

	public static void generateKeys() {

		System.out.println("\nStart generating RSA key");
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			pair = keyGen.generateKeyPair();
		} catch (Exception ex) {
			System.out.println(ex.toString());
		}

		System.out.println("Finish generating RSA key");

		rsaPriv = (RSAPrivateKey) pair.getPrivate();
		rsaPub = (RSAPublicKey) pair.getPublic();

	}

	public static byte[] Cypher(PrivateKey _priv, byte[] plainText) {

		try {

			System.out.println("Starting Cypher");
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

			cipher.init(Cipher.ENCRYPT_MODE, _priv);
			byte[] cipherText = cipher.doFinal(plainText);
			System.out.println("Finishing Cypher");

			return cipherText;

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	public static byte[] deCipher(PublicKey _pub, byte[] cipheredText) {

		try {

			System.out.println("Starting deCipher");
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

			cipher.init(Cipher.DECRYPT_MODE, _pub);
			byte[] decipheredText = cipher.doFinal(cipheredText);
			System.out.println("Finishing deCipher");

			return decipheredText;

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	public static byte[] Sign(PrivateKey privateKey, byte[] plaintext) {
		Signature instance = null;
		byte[] signature = null;
		try {
			instance = Signature.getInstance("SHA1withRSA");

			instance.initSign(privateKey);
			instance.update((plaintext));

			signature = instance.sign();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		} catch (SignatureException e) {
			e.printStackTrace();
			return null;
		}

		return signature;
	}

	public static boolean Verify(PublicKey publicKey, byte[] signature,
			byte[] data) {
		Signature instance = null;
		try {
			instance = Signature.getInstance("SHA1withRSA");

			instance.initVerify(publicKey);
			instance.update(data);

			return instance.verify(signature);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}

		return false;
	}

	public static RSAPrivateKey getRsaPriv() {
		return rsaPriv;
	}

	public static void setRsaPriv(RSAPrivateKey rsaPriv) {
		Security.rsaPriv = rsaPriv;
	}
}
