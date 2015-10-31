import java.security.*;
import java.security.cert.*;
import java.io.*;
import javax.crypto.*;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.params.*;
import javax.crypto.spec.IvParameterSpec;

public class AES {
	public static KeyStore openKeystore(String ks_path, char[] password) throws CertificateException, KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException {
		KeyStore ks = KeyStore.getInstance("BKS");
		java.io.FileInputStream fis = null;
		try {
			fis = new java.io.FileInputStream(ks_path);
			ks.load(fis, password);
		}
		finally {
			if (fis != null) {
				fis.close();
			}
		}
		return ks;
	}

	public static SecretKey openKey(KeyStore ks, String key_id, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException{
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
		KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry) ks.getEntry(key_id, protParam);
		return skEntry.getSecretKey();
	}

	public static char[] readPassword(String prompt) {
		Console cnsl = null;
		char [] password = null;
		try {
			cnsl = System.console();
			if (cnsl != null) {
				password = cnsl.readPassword(prompt);
			}
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return password;
	}

	public static byte[] encrypt(SecretKey key, byte[] cleartext, String mode) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException{
		byte[] ivBytes = new byte[] {
			0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
		};
		IvParameterSpec ivSpec  = new IvParameterSpec(ivBytes);
		Cipher cipher = Cipher.getInstance("AES/"+mode+"/PKCS5Padding");
		cipher.init(cipher.ENCRYPT_MODE, key, ivSpec);
		byte[] ciphertext = cipher.doFinal(cleartext);
		return ciphertext;
	}

	public static byte[] decrypt(SecretKey key, byte[] encrypted, String mode) throws NoSuchAlgorithmException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException {
		byte[] ivb = new byte[] {
			0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
		};
		IvParameterSpec ivs = new IvParameterSpec(ivb);
		Cipher cipher = Cipher.getInstance("AES/"+mode+"/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, ivs);
		byte[] plaintext = cipher.doFinal(encrypted);
		return plaintext;
	}

	public static String byteArrayToHexString(byte[] bytes) {
		final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
		char[] hexChars = new char[bytes.length * 2];
		int v;
		for ( int j = 0; j < bytes.length; j++ ) {
			v = bytes[j] & 0xFF;
			hexChars[j*2] = hexArray[v/16];
			hexChars[j*2 + 1] = hexArray[v%16];
		}
		return new String(hexChars);
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length() - 1;
		byte[] data = new byte[(len / 2)];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	private static String readFileAsString(String filePath) throws IOException {
		StringBuffer fileData = new StringBuffer();
		BufferedReader reader = new BufferedReader(new FileReader(filePath));
			char[] buf = new char[1024];
			int numRead=0;
			while((numRead=reader.read(buf)) != -1){
				String readData = String.valueOf(buf, 0, numRead);
				fileData.append(readData);
			}
		reader.close();
		return fileData.toString();
	}

	public static void main(String[] args) throws Exception {
		if (5 != args.length && 6 != args.length) {
			System.out.println("enc/dec plik tryb keystore id_klucza [wyjście]");
			System.exit(1);
		}
		String toenc = readFileAsString(args[1]);
		FileInputStream encryptedTextFis = new FileInputStream(args[1]);
		byte[] encText = new byte[encryptedTextFis.available()];
		encryptedTextFis.read(encText);
		encryptedTextFis.close();
		System.out.println("-- Wczytałem tekst: ");
		System.out.println(toenc);
		byte[] out = null;
		System.out.println(args[0]);
		if (args[0].equals("enc")) {
			System.out.println("-- Szyfruję…");
			out = encrypt(openKey(openKeystore(args[3], readPassword("Podaj hasło do keystore'a: ")), args[4], readPassword("Podaj hasło do klucza: ")), encText, args[2]);
		} else {
			System.out.println("-- Deszyfruję…");
			out = decrypt(openKey(openKeystore(args[3], readPassword("Podaj hasło do keystore'a: ")), args[4], readPassword("Podaj hasło do klucza: ")), encText, args[2]);
		}
		String output = new String(out);
		System.out.println("-- Wyjście:");
		System.out.println(output);
		if (6 == args.length) {
			System.out.println("-- Zapisałem wyjście do pliku "+args[5]);
			FileOutputStream keyfos = new FileOutputStream(args[5]);
			keyfos.write(out);
			keyfos.close();
		}
	}
}
