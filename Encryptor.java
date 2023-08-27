package nfm.main.entropy;

import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.*;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.iv.RandomIvGenerator;

//learn how to create a server so you can store the salt and have it unobtainable.
//honestly that's the only way I'll be using a file, no way will it be local else you lost all that's encrypted
//because they have access to your password and salt configuration. The XOR key found within this file
//can be viewed a decryptor or some other form of class viewer.

//and yeah same thing goes for XOR as well, not just salt

//..and perhaps password, too

// Upcoming plans:

// Encrypting the key and placing both input and encrypted key contents in a .zip file
// The issue with that currently being it's unable to decrypt it without having access
// to the key/IV itself... :/

// Instead, use the StandardPBEByteEncryptor and encrypt the file, just ask Bing AI
// what parameters to use such as algorithm, key iterations, etc.

// Encrypt password and XORkey pre-emptively, for just that slight extra sense of security

// add logging function (this should also apply in-game as well)

public class Encryptor {
    private StandardPBEByteEncryptor pbencryptor;
    private Charset charset;
    private SecretKey secretKey;
    private byte[] securityheader;
    private String xorKey;
    private String password;
    private String skfalgorithm;
    private String pbealgorithm;
    private String hashalgorithm;
    private int keySize;
    private int ivSize;
    private int saltSize;
    private int seedSize;
    private int iterations;
    private char[] xorKeyChars;
    private byte[] salt;
    private IvParameterSpec IV;
    
    //private static final String path;
    //private static final String[] encryptFiles;
    //private static final String[] decryptFiles;
    //private static final String keyFile;
    
    //private static final int bisBufferSize;
    //private static final int bosBufferSize;
    //private static final int inEncBufferSize;
    //private static final int inDecBufferSize;
    //private static final boolean encrypt;
    //private static final boolean decrypt;
    
    private String uppercasecharacters;
    private String lowercasecharacters;
    private String numbers;
    private String specialcharaters;
    private String passwordallowbase;
    private String passwordallowbaseshuffle;
    private String passwordallow;
    private int passwordlength;

    public void reset() {
        new Encryptor();
        
        // idk if this'll fail
        /*
        new Encryptor(this.pbealgorithm, this.password, this.iterations, this.skfalgorithm,
        this.hashalgorithm, this.keySize, generateSalt(), this.securityheader, this.xorKey,
        this.ivSize, this.saltSize, this.seedSize, this.charset);
        */
    }

    public void reset(byte[] salt) {
        new Encryptor(salt);
    }

    public void reset(String pbealgorithm, String password, int iterations,
    String skfalgorithm, String hashalgorithm, int key, byte[] salt,
    byte[] header, String xor, int iv, int size, int seed, Charset charset) {
        new Encryptor(pbealgorithm, password, iterations, skfalgorithm,
        hashalgorithm, key, salt, header, xor, iv, size, seed, charset);
    }

    public Encryptor() {
        this.pbinitialize("PBEWithHmacSHA512AndAES_256", "anNFMplayerisanidiot");
        this.saveRandomPasswordToFile("password.txt", 99);
        this.setIterationCount(65536);
        this.setSKFAlgorithm("PBEWithHmacSHA512AndAES_256");
        this.setHashAlgorithm("SHAKE256");//SHA3-512
        this.setKeySize(256);
        this.assignRandomSalt();
        this.assignRandomKey();
        //this.initializeKey(this.password, this.salt); //fails for some reason
        this.securityheader = new byte[] {
            -104, 62, -9, 0, 80, -75, 94, -1, 75, 1, -80
        };
        this.xorKeyChars = new char[16];
        this.setXORKey("still_an_idiot");
        this.setIVSize(12);
        this.setSaltSize(16);
        this.setSeedSize(16);
        this.setCharset(StandardCharsets.UTF_8);
    }

    public Encryptor(byte[] salt) {
        this.pbinitialize("PBEWithHmacSHA512AndAES_256", "anNFMplayerisanidiot");
        this.setIterationCount(65536);
        this.setSKFAlgorithm("PBEWithHmacSHA512AndAES_256");
        this.setHashAlgorithm("SHAKE256");//SHA3-512
        this.setKeySize(256);
        //this.initializeKey(this.password, salt);
        this.securityheader = new byte[] {
            -104, 62, -9, 0, 80, -75, 94, -1, 75, 1, -80
        };
        this.xorKeyChars = new char[16];
        this.setXORKey("still_an_idiot");
        this.setIVSize(12);
        this.setSaltSize(16);
        this.setSeedSize(16);
        this.setCharset(StandardCharsets.UTF_8);
    }

    public Encryptor(String pbealgorithm, String password, int iterations,
    String skfalgorithm, String hashalgorithm, int key, byte[] salt,
    byte[] header, String xor, int iv, int size, int seed, Charset charset) {
        this.pbinitialize(pbealgorithm, password);
        this.setIterationCount(iterations);
        this.setSKFAlgorithm(skfalgorithm);
        this.setHashAlgorithm(hashalgorithm);
        this.setKeySize(key);
        //this.initializeKey(this.password, salt);
        this.securityheader = header;
        this.xorKeyChars = new char[16];
        this.setXORKey(xor);
        this.setIVSize(iv);
        this.setSaltSize(size);
        this.setSeedSize(seed);
        this.setCharset(charset);
    }

    private byte[] generateSalt() {
        // Generate a random salt, with a specified size
        try {
            final byte[] salt = new byte[this.saltSize];
            final SecureRandom sr = new SecureRandom();
            sr.setSeed(sr.generateSeed(this.seedSize)); // Reseeding
            sr.nextBytes(salt);
            return salt;
        } catch (Exception e) {
            System.err.println("Error generating salt: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    private void assignRandomSalt() {
        this.salt = generateSalt();
    }
    
    public IvParameterSpec generateIV() {
        // Generate an IvParameterSpec, with randomly-generated IV bytes
        return new IvParameterSpec(generateIVBytes());
    }
    
    public IvParameterSpec generateSeededIV() {
        // Generate an IvParameterSpec, with randomly-generated IV bytes
        return new IvParameterSpec(generateSeededIVBytes());
    }
    
    public IvParameterSpec setIV(byte[] iv) {
        if (iv == null) {
            throw new NullPointerException("No IV was supplied");
        }
        // Return an IvParameterSpec, with the specified bytes in parameter
        return new IvParameterSpec(iv);
    }
    
    public byte[] generateIVBytes() {
        // Generate a random IV, with a specified size
        try {
            final byte[] iv = new byte[this.ivSize];
            new SecureRandom().nextBytes(iv);
            return iv;
        } catch (Exception e) {
            System.err.println("Error generating IV: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }
    
    public byte[] generateSeededIVBytes() {
        // Generate a random IV, with a specified size
        try {
            final byte[] iv = new byte[this.ivSize];
            final SecureRandom sr = new SecureRandom();
            sr.setSeed(sr.generateSeed(this.seedSize)); // Reseeding
            sr.nextBytes(iv);
            return iv;
        } catch (Exception e) {
            System.err.println("Error generating IV: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }
    
    public void assignRandomIV() {
        // Generate an IvParameterSpec, with randomly-generated IV bytes
        this.IV = generateIV();
    }
    
    public void assignRandomSeededIV() {
        // Generate an IvParameterSpec, with randomly-generated IV bytes
        this.IV = generateIV();
    }
    
    public void assignRandomIV(byte[] iv) {
        if (iv == null) {
            throw new NullPointerException("No IV was supplied");
        }
        // Generate an IvParameterSpec, with randomly-generated IV bytes
        this.IV = setIV(iv);
    }
    
    public String generateString() {
        if (this.passwordlength < 1) {
            System.err.println("Zero or negative length was supplied: " + this.passwordlength);
            return null;
        }
        return generateString(this.passwordlength);
    }
    
    public String generateString(int length) {
        if (length < 1) {
            System.err.println("Zero or negative length was supplied: " + length);
            return null;
        }
        StringBuilder sb = new StringBuilder(length);
        SecureRandom sr = new SecureRandom();
        for (int i = 0; i < length; i++) {
            int rndCharAt = sr.nextInt(passwordallow.length());
            char rndChar = passwordallow.charAt(rndCharAt);
            sb.append(rndChar);
        }
        return sb.toString();
    }

    public String shuffleString(String string) {
        if (string == null) {
            throw new NullPointerException("No string was supplied");
        }
        List<String> letters = Arrays.asList(string.split(""));
        Collections.shuffle(letters);
        return letters.stream().collect(Collectors.joining());
    }
    
    public SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(this.keySize);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error generating key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }
    
    public SecretKey generateWrappedKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(this.keySize);
            SecretKey key = keyGen.generateKey();
            SecretKey wrap = keyGen.generateKey();
            //Example of unwrapping key
            //SecretKey standardkey = this.unwrapKey(wrapped, warp);
            return this.wrapKey(key, wrap);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error generating key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }
    
    public SecretKey generateHashedKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(this.keySize);
            return this.hashKey(keyGen.generateKey());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error generating key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }
    
    public void assignRandomKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(this.keySize);
            this.secretKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating key: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error generating key: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    public void assignRandomWrappedKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(this.keySize);
            SecretKey key = keyGen.generateKey();
            SecretKey warp = keyGen.generateKey();
            //Example of unwrapping key
            //SecretKey standardkey = this.unwrapKey(wrapped, warp);
            this.secretKey = this.wrapKey(key, warp);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating key: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error generating key: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    public void assignRandomHashedKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(this.keySize);
            this.secretKey = this.hashKey(keyGen.generateKey());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating key: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error generating key: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private SecretKey deriveKey(String password, byte[] salt) {
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        if (salt == null) {
            throw new NullPointerException("No salt was supplied");
        }
        return this.deriveKey(password.toCharArray(), salt);
    }

    private SecretKey deriveKey(char[] password, byte[] salt) {
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        if (salt == null) {
            throw new NullPointerException("No salt was supplied");
        }
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(this.skfalgorithm);
            KeySpec spec = new PBEKeySpec(password, salt, this.iterations, this.keySize);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Error deriving key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error deriving key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public void saveRandomPasswordToFile(String file, int length) { //temporary
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        if (length < 1) {
            throw new IllegalArgumentException("Zero or negative length was supplied: " + length);
        }
        // Write out the key and IV parameters as bytes, with a preferred buffer size
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file), 1024)) {
            bw.write(generateString(length));
        } catch (IOException e) {
            System.err.println("Error writing key bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing key bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void saveKeyToFile(SecretKey key, String file) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        // Write out the key and IV parameters as bytes, with a preferred buffer size
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file), 1024)) {//bosBufferSize
            bos.write(key.getEncoded());
        } catch (IOException e) {
            System.err.println("Error writing key bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing key bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void saveKeyToFile(SecretKey key, String file, boolean overwrite) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        // Write out the key and IV parameters as bytes, with a preferred buffer size
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file, overwrite), 1024)) {//bosBufferSize
            bos.write(key.getEncoded());
        } catch (IOException e) {
            System.err.println("Error writing key bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing key bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void saveIvToFile(IvParameterSpec iv, String file) {
        if (iv == null) {
            throw new NullPointerException("No iv was supplied");
        }
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        // Write out the key and IV parameters as bytes, with a preferred buffer size
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file, true), 1024)) {//bosBufferSize
            bos.write(iv.getIV());
        } catch (IOException e) {
            System.err.println("Error writing IV bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing IV bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void saveIvToFile(IvParameterSpec iv, String file, boolean overwrite) {
        if (iv == null) {
            throw new NullPointerException("No iv was supplied");
        }
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        // Write out the key and IV parameters as bytes, with a preferred buffer size
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file, overwrite), 1024)) {//bosBufferSize
            bos.write(iv.getIV());
        } catch (IOException e) {
            System.err.println("Error writing IV bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing IV bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void saveKeysToFile(SecretKey key, IvParameterSpec iv, String file) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (iv == null) {
            throw new NullPointerException("No iv was supplied");
        }
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        // Write out the key and IV parameters as bytes, with a preferred buffer size
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file), 1024)) {//bosBufferSize
            bos.write(key.getEncoded());
            bos.write(iv.getIV());
        } catch (IOException e) {
            System.err.println("Error writing key and IV bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing key and IV bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void saveKeysToFile(SecretKey key, IvParameterSpec iv, String file, boolean overwrite) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (iv == null) {
            throw new NullPointerException("No iv was supplied");
        }
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        // Write out the key and IV parameters as bytes, with a preferred buffer size
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file, overwrite), 1024)) {//bosBufferSize
            bos.write(key.getEncoded());
            bos.write(iv.getIV());
        } catch (IOException e) {
            System.err.println("Error writing key and IV bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing key and IV bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public SecretKey loadKeyFromFile(String file) {
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        return this.loadKeyFromFile(file, 0);
    }

    public SecretKey loadKeyFromFile(String file, int offset) {
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        if (offset < 0) {
            System.err.println("Negative offset was supplied: " + offset);
            return null;
        }
        // Read the key and IV parameters as bytes, with a preferred buffer size
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            // Set the key bytes using a preferred size
            byte[] keyBytes = new byte[this.keySize];
            byte[] buffer = new byte[1024];//bisBufferSize
            int bytesRead = bis.read(buffer, offset, this.keySize);
            if (bytesRead != this.keySize) {
                throw new IOException("Bytes read does not match key array");
            } else {
                // Copy the data from the buffer into the keyBytes array
                System.arraycopy(buffer, offset, keyBytes, 0, bytesRead);
            }
            /*
            byte[] buffer = new byte[1024];//bisBufferSize
            int offset = 0;
            int length = 100; // Number of bytes to read
            int bytesRead;
            while ((bytesRead = bis.read(buffer, offset, length)) != -1) {
                // Process the data in the buffer
                offset += bytesRead;
            }
            bis.skip(offset); // Skip over the IV data
            bis.read(ivBytes);
            */
           
            // Initialize the key using the existing key bytes
            return new SecretKeySpec(keyBytes, "AES");
        } catch (IOException e) {
            System.err.println("Error reading key bytes: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error reading key bytes: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public IvParameterSpec loadIvFromFile(String file) {
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        return this.loadIvFromFile(file, 0);
    }

    public IvParameterSpec loadIvFromFile(String file, int offset) {
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        if (offset < 0) {
            System.err.println("Negative offset was supplied: " + offset);
            return null;
        }
        // Read the key and IV parameters as bytes, with a preferred buffer size
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            // Set the key bytes using a preferred size
            byte[] ivBytes = new byte[this.ivSize];
            byte[] buffer = new byte[1024];//bisBufferSize
            int bytesRead = bis.read(buffer, offset, this.ivSize);
            if (bytesRead != this.ivSize) {
                throw new IOException("Bytes read does not match IV array");
            } else {
                // Copy the data from the buffer into the keyBytes array
                System.arraycopy(buffer, offset, ivBytes, 0, bytesRead);
            }
            /*
            byte[] buffer = new byte[1024];//bisBufferSize
            int offset = 0;
            int length = 100; // Number of bytes to read
            int bytesRead;
            while ((bytesRead = bis.read(buffer, offset, length)) != -1) {
                // Process the data in the buffer
                offset += bytesRead;
            }
            bis.skip(offset); // Skip over the IV data
            bis.read(ivBytes);
            */
            // Return both instances as an array of objects
            return new IvParameterSpec(ivBytes);
        } catch (IOException e) {
            System.err.println("Error reading IV bytes: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error reading IV bytes: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public Object[] loadKeysFromFile(String file) {
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        return this.loadKeysFromFile(file, 0);
    }

    public Object[] loadKeysFromFile(String file, int offset) {
        if (file == null) {
            //throw new NullPointerException("No file was supplied");
        }
        if (offset < 0) {
            System.err.println("Negative offset was supplied: " + offset);
            //return null;
        }
        // Read the key and IV parameters as bytes, with a preferred buffer size
            // Set the key bytes using a preferred size
            byte[] keyBytes = new byte[this.keySize];
            byte[] ivBytes = new byte[this.ivSize];
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            /*
            byte[] buffer = new byte[1024];//bisBufferSize
            int bytesRead = bis.read(buffer, 0, this.keySize + this.ivSize);
            if (bytesRead != this.keySize) {
                throw new IOException("Bytes read does not match key array");
            } else {
                // Copy the data from the buffer into the keyBytes array
                System.arraycopy(buffer, 0, keyBytes, 0, bytesRead);
                System.arraycopy(buffer, offset, ivBytes, 0, bytesRead);
            }
            */
            /*
            byte[] buffer = new byte[1024];//bisBufferSize
            int offset = 0;
            int length = 100; // Number of bytes to read
            int bytesRead;
            while ((bytesRead = bis.read(buffer, offset, length)) != -1) {
                // Process the data in the buffer
                offset += bytesRead;
            }
            bis.skip(offset); // Skip over the IV data
            bis.read(ivBytes);
            */
            bis.read(keyBytes);
            bis.read(ivBytes);
        } catch (IOException e) {
            System.err.println("Error reading key bytes: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error reading key bytes: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
            
            // Initialize the key using the existing key bytes
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            
            // Initialize the key using the existing IV bytes
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
           
            // Return both instances as an array of objects
            return new Object[]{key, iv};
        //return null;
    }

    public byte[] setSalt() {
        return setSalt(this.password, this.charset);
    }

    public byte[] setSalt(String password) {
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        return setSalt(password, this.charset);
    }

    public byte[] setSalt(Charset charset) {
        if (charset == null) {
            throw new NullPointerException("No charset was supplied");
        }
        return setSalt(this.password, charset);
    }

    public byte[] setSalt(String password, Charset charset) {
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        if (charset == null) {
            throw new NullPointerException("No charset was supplied");
        }
        while (password.getBytes(charset).length < 16) {
            password += password;
        }
        byte[] salt = password.getBytes(charset);
        if (salt.length > 16) {
            salt = Arrays.copyOfRange(salt, 0, 16);
        }
        return salt;
    }

    public void pbinitialize() {
        if (this.pbealgorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        if (this.password == null) {
            throw new NullPointerException("No password was supplied");
        }
        this.pbinitialize(this.pbealgorithm, this.password);
    }

    public void pbinitialize(String algorithm) {
        if (algorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        if (this.password == null) {
            throw new NullPointerException("No password was supplied");
        }
        this.pbinitialize(algorithm, this.password);
    }

    public void pbinitialize2(String password) {
        if (this.pbealgorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        this.pbinitialize(this.pbealgorithm, password);
    }

    public void pbinitialize(String algorithm, String password) {
        if (algorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        uppercasecharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        lowercasecharacters = uppercasecharacters.toLowerCase();
        numbers = "0123456789";
        specialcharaters = "!@#$%&*()_+-=[]?|\"\'/\\:;<>{}^~`";
        passwordallowbase = uppercasecharacters
        + lowercasecharacters + numbers + specialcharaters;
        passwordallowbaseshuffle = shuffleString(passwordallowbase);
        passwordallow = passwordallowbaseshuffle;
        //this.setPasswordLength(20);
        this.pbencryptor = new StandardPBEByteEncryptor();
        this.setPBEAlgorithm(algorithm);
        if (password == null || password == "") {
            //this.setPassword(this.generatePassword());
        }
        this.setPassword(password);
        this.setPasswordLength(this.password.length());
        this.pbencryptor.setIvGenerator(new RandomIvGenerator()); // Set the IV generator
        this.pbencryptor.initialize();
    }
    
    public void initializeKey(String password, byte[] salt) {
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        if (salt == null) {
            throw new NullPointerException("No salt was supplied");
        }
        this.secretKey = deriveKey(password, salt);
    }
    
    public void initializeKey(char[] password, byte[] salt) {
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        if (salt == null) {
            throw new NullPointerException("No salt was supplied");
        }
        this.secretKey = deriveKey(password, salt);
    }

    public void setPBEAlgorithm() {
        if (this.pbealgorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        this.pbencryptor.setAlgorithm(this.pbealgorithm);
    }

    public void setPBEAlgorithm(String algorithm) {
        if (algorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        this.pbealgorithm = algorithm;
        this.pbencryptor.setAlgorithm(this.pbealgorithm);
    }

    public void setSKFAlgorithm(String algorithm) {
        if (algorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        this.skfalgorithm = algorithm;
    }

    public void setHashAlgorithm(String algorithm) {
        if (algorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        this.hashalgorithm = algorithm;
    }

    public void setCharset(Charset charset) {
        if (charset == null) {
            throw new NullPointerException("No charset was supplied");
        }
        this.charset = charset;
    }

    public void setXORKey(String key) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        this.xorKey = key;
    }

    public void setXORKey(char[] key) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        this.setXORKey(String.valueOf(key));
    }

    public void setPassword(String password) {
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        this.password = password;
        this.pbencryptor.setPassword(this.password);
    }

    public void setPassword(char[] password) {
        if (password == null) {
            throw new NullPointerException("No password was supplied");
        }
        this.password = String.valueOf(password);
        this.pbencryptor.setPasswordCharArray(password);
    }

    public void setPasswordLength(int length) {
        if (length < 1) {
            throw new IllegalArgumentException("Zero or negative length was supplied: " + length);
        }
        this.passwordlength = length;
    }

    public void setKeySize(int size) {
        if (size < 1) {
            throw new IllegalArgumentException("Zero or negative size was supplied: " + size);
        }
        this.keySize = size;
    }

    public void setIVSize(int size) {
        if (size < 1) {
            throw new IllegalArgumentException("Zero or negative size was supplied: " + size);
        }
        this.ivSize = size;
    }

    public void setSeedSize(int size) {
        if (size < 1) {
            throw new IllegalArgumentException("Zero or negative size was supplied: " + size);
        }
        this.seedSize = size;
    }

    public void setSaltSize(int size) {
        if (size < 1) {
            throw new IllegalArgumentException("Zero or negative size was supplied: " + size);
        }
        this.saltSize = size;
    }

    public void setIterationCount(int count) {
        if (count < 1) {
            throw new IllegalArgumentException("Zero or negative count was supplied: " + count);
        }
        this.iterations = count;
    }

    public byte[] performXOR(String data, String key) {
        if (data == null) {
            throw new NullPointerException("No data was supplied");
        }
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        return this.performXOR(this.stringToBytes(data), key);
    }

    public byte[] performXOR(String data, char[] key) {
        if (data == null) {
            throw new NullPointerException("No data was supplied");
        }
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        return this.performXOR(this.stringToBytes(data), key);
    }

    public byte[] performXOR(byte[] data, String key) {
        if (data == null) {
            throw new NullPointerException("No data was supplied");
        }
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        try {
            key.getChars(0, key.length(), xorKeyChars, 0);
            byte[] output = new byte[data.length];
            for (int i = data.length - 1; i >= 0; --i) {
                output[i] = (byte)(data[i] ^ xorKeyChars[i % xorKeyChars.length]);
            }
            return output;
        } catch (Exception e) {
            // Handle exceptions
            System.err.println("Error performing XOR: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public byte[] performXOR(byte[] data, char[] key) {
        if (data == null) {
            throw new NullPointerException("No data was supplied");
        }
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        try {
            byte[] output = new byte[data.length];
            for (int i = data.length - 1; i >= 0; --i) {
                output[i] = (byte)(data[i] ^ xorKeyChars[i % xorKeyChars.length]);
            }
            return output;
        } catch (Exception e) {
            // Handle exceptions
            System.err.println("Error performing XOR: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public byte[] pbencrypt(byte[] plaintext) {
        if (plaintext == null) {
            throw new NullPointerException("No data was supplied");
        }
        try {
            return this.pbencryptor.encrypt(plaintext);
        } catch (Exception e) {
            System.err.println("Error encrypting bytes: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public byte[] pbdecrypt(byte[] encryptedMessage) {
        if (encryptedMessage == null) {
            throw new NullPointerException("No data was supplied");
        }
        try {
            return this.pbencryptor.decrypt(encryptedMessage);
        } catch (Exception e) {
            System.err.println("Error decrypting bytes: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public void encryptKeysToFile(SecretKey key, IvParameterSpec iv, String[] file) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (iv == null) {
            throw new NullPointerException("No IV was supplied");
        }
        if (file == null) {
            throw new NullPointerException("No files were supplied");
        }
        if (file[0] == null) {
            throw new NullPointerException("No input was supplied");
        }
        if (file[1] == null) {
            throw new NullPointerException("No output was supplied");
        }
        
        /*
         * The following commented-out block of code is designed to showcase key and IV rotation.
         * Rotating a key directly after generating a new one is not necessary, in fact it's
         * redundant as it wastes time and computational resources.
         * Please take proper caution and ensure the IV and key are saved when rotating both
         * instances.
         */
        
        /*
        // Load the secret key from the file and initialize it for use with re-encryption
        SecretKey key = loadKeyFromFile(file);
        
        // Load the IV from the file and initialize it for use with re-encryption
        IvParameterSpec iv = loadIvFromFile(file, this.keySize);
        
        // Re-generate a random secret key, with a specified size in bytes converted to bits
        key = this.generateKey();

        // Re-generate a random IV, with a specified size in bytes converted to bits
        iv = this.generateIV();
        
        // Save the key to a file
        saveKeyToFile(key, file);
        
        // Save the IV to a file
        saveIvToFile(iv, file);
        */
       
        // Encrypt the input file
        try (FileInputStream in = new FileInputStream(file[0]);
             FileOutputStream out = new FileOutputStream(file[1])) {
            encryptFile(key, iv, in, out);
        } catch (IOException e) {
            System.err.println("Error writing file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void encryptKeysToFile(SecretKey key, IvParameterSpec iv, String file, String[] files) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (iv == null) {
            throw new NullPointerException("No IV was supplied");
        }
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        if (files == null) {
            throw new NullPointerException("No files were supplied");
        }
        if (files[0] == null) {
            throw new NullPointerException("No input was supplied");
        }
        if (files[1] == null) {
            throw new NullPointerException("No output was supplied");
        }
        
        // Save the key to a file
        //saveKeyToFile(key, file, false);
        
        // Save the IV to a file
        //saveIvToFile(iv, file, true);
        
        saveKeysToFile(key, iv, file);
        
        /*
         * The following commented-out block of code is designed to showcase key and IV rotation.
         * Rotating a key directly after generating a new one is not necessary, in fact it's
         * redundant as it wastes time and computational resources.
         * Please take proper caution and ensure the IV and key are saved when rotating both
         * instances.
         */
        
        /*
        // Load the secret key from the file and initialize it for use with re-encryption
        SecretKey key = loadKeyFromFile(file);
        
        // Load the IV from the file and initialize it for use with re-encryption
        IvParameterSpec iv = loadIvFromFile(file, this.keySize);
        
        // Re-generate a random secret key, with a specified size in bytes converted to bits
        key = this.generateKey();

        // Re-generate a random IV, with a specified size in bytes converted to bits
        iv = this.generateIV();
        
        // Save the key to a file
        saveKeyToFile(key, file);
        
        // Save the IV to a file
        saveIvToFile(iv, file);
        */
       
        // Encrypt the input file
        try (FileInputStream in = new FileInputStream(files[0]);
             FileOutputStream out = new FileOutputStream(files[1])) {
            encryptFile(key, iv, in, out);
        } catch (IOException e) {
            System.err.println("Error writing file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void encryptKeysToFile(String[] file) {
        if (file == null) {
            throw new NullPointerException("No files were supplied");
        }
        if (file[0] == null) {
            throw new NullPointerException("No input was supplied");
        }
        if (file[1] == null) {
            throw new NullPointerException("No output was supplied");
        }
        // Generate a random secret key, with a specified size in bytes converted to bits
        SecretKey key = this.generateKey();

        // Generate a random IV, with a specified size in bytes converted to bits
        //apparently it's supposed to support 128-bit (16 bytes) but it shows encrypted content as 0KB
        IvParameterSpec iv = this.generateIV();
        
        this.encryptKeysToFile(key, iv, file);
    }

    public void encryptKeysToFile(String file, String[] files) {
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        if (files == null) {
            throw new NullPointerException("No files were supplied");
        }
        if (files[0] == null) {
            throw new NullPointerException("No input was supplied");
        }
        if (files[1] == null) {
            throw new NullPointerException("No output was supplied");
        }
        // Generate a random secret key, with a specified size in bytes converted to bits
        SecretKey key = this.generateKey();

        // Generate a random IV, with a specified size in bytes converted to bits
        //apparently it's supposed to support 128-bit (16 bytes) but it shows encrypted content as 0KB
        IvParameterSpec iv = this.generateIV();
        
        this.encryptKeysToFile(key, iv, file, files);
    }

    public void decryptKeysToFile(String file, String[] files) {
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        if (files == null) {
            throw new NullPointerException("No files were supplied");
        }
        if (files[0] == null) {
            throw new NullPointerException("No input was supplied");
        }
        if (files[1] == null) {
            throw new NullPointerException("No output was supplied");
        }
        // Load the secret key from the file and initialize it for use with decryption
        //SecretKey key = loadKeyFromFile(file);
        
        // Load the IV from the file and initialize it for use with decryption
        //IvParameterSpec iv = loadIvFromFile(file, this.keySize);
        
        // Load the key and IV from the file
        Object[] keys = loadKeysFromFile(file);
        
        // Initialize the secret key for use with decryption
        SecretKey key = (SecretKey) keys[0];
        
        // Initialize the IV for use with decryption
        IvParameterSpec iv = (IvParameterSpec) keys[1];
        
        // Decrypt the encrypted file
        try (FileInputStream in = new FileInputStream(files[0]);
             FileOutputStream out = new FileOutputStream(files[1])) {
            decryptFile(key, iv, in, out);
        } catch (IOException e) {
            System.err.println("Error writing file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void encryptFile(SecretKey key, IvParameterSpec iv, InputStream in, OutputStream out) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (iv == null) {
            throw new NullPointerException("No IV was supplied");
        }
        if (in == null) {
            throw new NullPointerException("No input stream was supplied");
        }
        if (out == null) {
            throw new NullPointerException("No output stream was supplied");
        }
        try {
            // Set the cipher found in org.bouncycastle.crypto.modes
            AEADBlockCipher cipher = new GCMSIVBlockCipher(AESEngine.newInstance());
            
            // Initialize the cipher (boolean defines encryption)
            cipher.init(true, new AEADParameters(new KeyParameter(key.getEncoded()), 128, iv.getIV()));
            
            // Set the buffer (based on the preferred size)
            byte[] buffer = new byte[8192];//inEncBufferSize
            
            int bytesRead;
            
            // Read the bytes within the input stream
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] ciphertext = new byte[cipher.getOutputSize(bytesRead)];
                int len = cipher.processBytes(buffer, 0, bytesRead, ciphertext, 0);
                out.write(ciphertext, 0, len);
            }
            
            // Ensure all data has been fully written
            out.flush();
            
            // Grab the bytes from the cipher
            byte[] finalCiphertext = new byte[cipher.getOutputSize(0)];
            
            // Encrypt the ciphertext
            int len = cipher.doFinal(finalCiphertext, 0);
            
            // Write out the encrypted bytes as an output stream
            out.write(finalCiphertext, 0, len);
            
            // Ensure all data has been fully written
            out.flush();
            
            // Close the output stream
            out.close();
        } catch (InvalidCipherTextException | IOException e) {
            System.err.println("Error encrypting file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error encrypting file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void decryptFile(SecretKey key, IvParameterSpec iv, InputStream in, OutputStream out) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (iv == null) {
            throw new NullPointerException("No IV was supplied");
        }
        if (in == null) {
            throw new NullPointerException("No input stream was supplied");
        }
        if (out == null) {
            throw new NullPointerException("No output stream was supplied");
        }
        try {
            // Set the cipher found in org.bouncycastle.crypto.modes
            AEADBlockCipher cipher = new GCMSIVBlockCipher(AESEngine.newInstance());
            
            // Initialize the cipher (boolean defines encryption)
            cipher.init(false, new AEADParameters(new KeyParameter(key.getEncoded()), 128, iv.getIV()));
            
            // Set the buffer (based on the preferred size)
            byte[] buffer = new byte[8192];//inEncBufferSize
            
            int bytesRead;
            
            // Read the bytes within the input stream
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] ciphertext = new byte[cipher.getOutputSize(bytesRead)];
                int len = cipher.processBytes(buffer, 0, bytesRead, ciphertext, 0);
                out.write(ciphertext, 0, len);
            }
            
            // Ensure all data has been fully written
            out.flush();
            
            // Grab the bytes from the cipher
            byte[] finalCiphertext = new byte[cipher.getOutputSize(0)];
            
            // Encrypt the ciphertext
            int len = cipher.doFinal(finalCiphertext, 0);
            
            // Write out the encrypted bytes as an output stream
            out.write(finalCiphertext, 0, len);
            
            // Ensure all data has been fully written
            out.flush();
            
            // Close the output stream
            out.close();
        } catch (InvalidCipherTextException | IOException e) {
            System.err.println("Error decrypting file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error decrypting file: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public SecretKey wrapKey(SecretKey keyToWrap, SecretKey wrappingKey) {
        if (keyToWrap == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (wrappingKey == null) {
            throw new NullPointerException("No output was supplied");
        }
        try {
            AESWrapEngine engine = new AESWrapEngine();
            engine.init(true, new KeyParameter(wrappingKey.getEncoded()));
            byte[] wrappedKey = engine.wrap(keyToWrap.getEncoded(), 0, keyToWrap.getEncoded().length);
            return new SecretKeySpec(wrappedKey, "AES");
        } catch (Exception e) {
            System.err.println("Error wrapping key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public SecretKey unwrapKey(SecretKey wrappedKey, SecretKey unwrappingKey) {
        if (wrappedKey == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (unwrappingKey == null) {
            throw new NullPointerException("No output was supplied");
        }
        try {
            AESWrapEngine engine = new AESWrapEngine();
            engine.init(false, new KeyParameter(unwrappingKey.getEncoded()));
            byte[] unwrappedKey = engine.unwrap(wrappedKey.getEncoded(), 0, wrappedKey.getEncoded().length);
            return new SecretKeySpec(unwrappedKey, "AES");
        } catch (InvalidCipherTextException e) {
            System.err.println("Error unwrapping key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error unwrapping key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }
    
    public SecretKey hashKey(SecretKey key) {
        if (key == null) {
            throw new NullPointerException("No key was supplied");
        }
        if (this.hashalgorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        try {
            MessageDigest md = MessageDigest.getInstance(this.hashalgorithm);
            byte[] hashedKey = md.digest(key.getEncoded());
            return new SecretKeySpec(hashedKey, "AES");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error hashing key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error hashing key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }
    
    public SecretKey getHashedKey(String file) {//throws NoSuchAlgorithmException
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        if (this.hashalgorithm == null) {
            throw new NullPointerException("No algorithm was supplied");
        }
        try {
            byte[] buffer = new byte[8192];
            int count;
            MessageDigest md = MessageDigest.getInstance(this.hashalgorithm);
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
            while ((count = bis.read(buffer)) > 0) {
                md.update(buffer, 0, count);
            }
            bis.close();
            byte[] hash = md.digest();
            return new SecretKeySpec(hash, "AES");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error hashing key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error hashing key: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public byte[] stringToBytes(String string) {
        if (string == null) {
            throw new NullPointerException("No string was supplied");
        }
        try {
            return string.getBytes(this.charset);
        } catch (Exception e) {
            // Handle exceptions
            System.err.println("Error converting string to bytes: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public String bytesToString(byte[] bytes) {
        if (bytes == null) {
            throw new NullPointerException("No data were supplied");
        }
        try {
            return new String(bytes, this.charset);
        } catch (Exception e) {
            // Handle exceptions
            System.err.println("Error converting bytes to string: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public byte[] readBytes(byte[] bytes) {
        if (bytes == null) {
            throw new NullPointerException("No data were supplied");
        }
        // Check if the file is encrypted by looking for the custom header
        boolean isEncrypted = false;
        if (bytes.length > securityheader.length) {
            isEncrypted = true;
            for (int i = 0; i < securityheader.length; i++) {
                if (bytes[i] != securityheader[i]) {
                    isEncrypted = false;
                    break;
                }
            }
        }

        if (isEncrypted) {
            // Remove the custom header from the file bytes
            bytes = Arrays.copyOfRange(bytes, securityheader.length, bytes.length);

            try {
                bytes = this.pbdecrypt(bytes);
                bytes = this.performXOR(bytes, this.xorKey);
            } catch (Exception e) {
                // Handle the exception here
                System.err.println("Error decrypting or performing XOR on file bytes: " + e.getMessage());
                System.err.println("Error: " + e);
                e.printStackTrace();
                return null;
            }
        }
        
        return bytes;
    }

    public byte[] fileToBytes(String file, boolean decrypt) throws IOException {
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
        } catch (IOException ex) {// | IllegalArgumentException //why was this necessary?
            throw ex;
        }

        byte[] fileBytes = baos.toByteArray();
        
        // Check if the file is encrypted by looking for the custom header
        boolean isEncrypted = false;
        if (fileBytes.length > securityheader.length) {
            isEncrypted = true;
            for (int i = 0; i < securityheader.length; i++) {
                if (fileBytes[i] != securityheader[i]) {
                    isEncrypted = false;
                    break;
                }
            }
        }

        if (isEncrypted && decrypt) {
            // Remove the custom header from the file bytes
            fileBytes = Arrays.copyOfRange(fileBytes, securityheader.length, fileBytes.length);

            try {
                fileBytes = this.pbdecrypt(fileBytes);
                fileBytes = this.performXOR(fileBytes, this.xorKey);
            } catch (Exception e) {
                // Handle the exception here
                System.err.println("Error decrypting or performing XOR on file bytes: " + e.getMessage());
                System.err.println("Error: " + e);
                e.printStackTrace();
                return null;
            }
        }

        return fileBytes;
    }

    public void bytesToFile(byte[] bytes, String file, boolean encrypt) {
        if (bytes == null) {
            throw new NullPointerException("No data was supplied");
        }
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file))) {
            if (encrypt) {
                try {
                    bytes = this.performXOR(bytes, this.xorKey);
                    bytes = this.pbencrypt(bytes);

                    // Write the custom header to the output file
                    bos.write(securityheader);
                } catch (Exception e) {
                    // Handle the exception here
                    System.err.println("Error encrypting or performing XOR on file bytes: " + e.getMessage());
                    System.err.println("Error: " + e);
                    e.printStackTrace();
                    return;
                }
            }

            bos.write(bytes);
        } catch (IOException e) {
            System.err.println("Error writing bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Error writing bytes: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    private byte[] extractSalt(String file) {
        if (file == null) {
            throw new NullPointerException("No file was supplied");
        }
        // Create a byte array to store the salt value
        byte[] salt = new byte[16];

        // Open the encrypted file as an input stream
        try (FileInputStream fis = new FileInputStream(file)) {
            // Read the first 16 bytes of the encrypted file into the salt array
            fis.read(salt);
            return salt;
        } catch (IOException e) {
            System.err.println("Error extracting salt: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error extracting salt: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        System.out.println("Initializing encryption service...");
        
        // Call this class' methods to initialize the encryptor
        Encryptor encryptor = new Encryptor();
        
        // Generate a random salt
        //encryptor.salt = encryptor.generateSalt();
        encryptor.assignRandomSalt();
        
        byte[] salt = encryptor.generateSalt();
        
        // For some reason, encryptor.salt (aka the general salt value) doesn't work
        // when decryption is attempted using the byte array
        // As a result, any encryptor.salt instance can be disregarded in this case
        
        // Initialize the salt for use with the encryptor
        //encryptor = new Encryptor(salt);//encryptor.salt

        // Initialize files for byte-swapping data transformation
        String[] inputFilePath = new String[] {
            "save.radq", "password.txt"
        };
        
        // ZIP file alternative
        String[][] zipInputFiles = new String[][] {
            {
            "save.nfm", "saved.nfm"
            }
        };
        
        // Set the input file path for the ZIP file
        String[] zipInputFile = new String[] {
            "saved.radq"
        };
        
        // Set up the encrypted file path arrays for input files
        String[] encryptedFilePath = new String[inputFilePath.length];
        for (int a = 0; a < inputFilePath.length; a++) {
            encryptedFilePath[a] = inputFilePath[a].substring(0, inputFilePath[a].lastIndexOf(".")) + "enc" + inputFilePath[a].substring(inputFilePath[a].lastIndexOf("."));
        }

        // Set up the decrypted file path arrays for input files
        String[] decryptedFilePath = new String[inputFilePath.length];
        for (int a = 0; a < inputFilePath.length; a++) {
            decryptedFilePath[a] = inputFilePath[a].substring(0, inputFilePath[a].lastIndexOf(".")) + "dec" + inputFilePath[a].substring(inputFilePath[a].lastIndexOf("."));
        }
        
        // Set up the encrypted file path arrays for zip files
        String[] encryptedZipOutput = new String[zipInputFile.length];
        for (int a = 0; a < zipInputFile.length; a++) {
            encryptedZipOutput[a] = zipInputFile[a].substring(0, zipInputFile[a].lastIndexOf(".")) + "enc" + zipInputFile[a].substring(zipInputFile[a].lastIndexOf("."));
        }

        // Set up the decrypted file path arrays for zip files
        String[] decryptedZipOutput = new String[zipInputFile.length];
        for (int a = 0; a < zipInputFile.length; a++) {
            decryptedZipOutput[a] = zipInputFile[a].substring(0, zipInputFile[a].lastIndexOf(".")) + "dec" + zipInputFile[a].substring(zipInputFile[a].lastIndexOf("."));
        }

        // Set up the encryptor to encrypt the files located within inputFilePath and zipInputFiles
        boolean[] encrypt = new boolean[] {//first boolean for inputFilePath, second zipInputFiles
            true, true//false, true
        };

        // Set up the encryptor to decrypt the files located within inputFilePath and zipInputFiles
        boolean[] decrypt = new boolean[] {//first boolean for inputFilePath, second zipInputFiles
            true, true//false, true
        };

        // Set up the encryptor to start data transformation
        boolean[] init = new boolean[] {//first boolean for inputFilePath, second zipInputFiles
            false, false//false, true
        };

        // Set up the zipInputFile portion of the encryptor
        // to create a compressed .zip based on specified files
        boolean create = true;

        // Set up the zipInputFile portion of the encryptor
        // to overwrite a compressed .zip, if one exists, based on specified files
        boolean overwrite = true;
        
        encryptor.encryptKeysToFile("thekey.txt", new String[]{"save.radq", "saven.radq"});
        encryptor.decryptKeysToFile("thekey.txt", new String[]{"saven.radq", "saveo.radq"});

        try {
            if (zipInputFile.length > 0) {
                if (init[1]) {
                    for (int a = 0; a < zipInputFile.length; a++) {
                        File f = new File(zipInputFile[a]);
                        if (f.exists() && overwrite || create) {
                            // Compress the input files into a single ZIP file
                            ByteArrayOutputStream baos = new ByteArrayOutputStream();
                            ZipOutputStream zos = new ZipOutputStream(baos);
                            for (String zipFile : zipInputFiles[a]) {
                                // Read the input file as a byte array
                                byte[] zipFileBytes = encryptor.fileToBytes(zipFile, false);

                                // Create a new ZipEntry for the input file
                                ZipEntry entry = new ZipEntry(zipFile);
                                zos.putNextEntry(entry);

                                // Write the input file bytes to the ZipEntry
                                zos.write(zipFileBytes);

                                // Close the ZipEntry
                                zos.closeEntry();
                            }
                            zos.close();
                            byte[] encryptedBytes = baos.toByteArray();

                            // Write the compressed bytes to the output file
                            encryptor.bytesToFile(encryptedBytes, zipInputFile[a], false);
                        }
                        if (f.exists()) {
                            if (encrypt[1]) {
                                // Read the encrypted file as a byte array to be encrypted
                                byte[] encryptedBytes = encryptor.fileToBytes(zipInputFile[a], false);

                                // Encrypt the compressed bytes and write them to the output file
                                encryptor.bytesToFile(encryptedBytes, encryptedZipOutput[a], true);
                            }
                            
                            if (decrypt[1]) {
                                // Set the salt
                                //encryptor.salt = encryptor.extractSalt(encryptedZipOutput[a]);//zipInputFile[a]
                                //salt = encryptor.extractSalt(encryptedZipOutput[a]);//zipInputFile[a]
                                
                                // Call this class' methods to initialize the encryptor
                                //encryptor = new Encryptor(salt);//encryptor.salt
                            
                                // Read the encrypted file as a byte array to be decrypted
                                byte[] decryptedFileBytes = encryptor.fileToBytes(encryptedZipOutput[a], true);//zipInputFile[a]

                                // Write the decrypted bytes to the output file
                                encryptor.bytesToFile(decryptedFileBytes, decryptedZipOutput[a], false);
                            }
                        } else {
                            System.err.println("File " + f.getAbsolutePath() + " does not exist");
                            //continue; //not necessary, it's at the end of the line anyway
                        }
                    }
                }
            }
            if (inputFilePath.length > 0) {
                if (init[0]) {
                    for (int a = 0; a < inputFilePath.length; a++) {
                        File f = new File(inputFilePath[a]);
                        if (f.exists()) {
                            if (encrypt[0]) {
                                // Read the input file as a byte array to be encrypted
                                byte[] encryptedFileBytes = encryptor.fileToBytes(inputFilePath[a], false);

                                // Write the encrypted bytes to the output file
                                encryptor.bytesToFile(encryptedFileBytes, encryptedFilePath[a], true);
                            }
                            
                            if (decrypt[0]) {
                                // Set the salt
                                //encryptor.salt = encryptor.extractSalt(encryptedFilePath[a]);//inputFilePath[a]
                                //salt = encryptor.extractSalt(encryptedFilePath[a]);//inputFilePath[a]
                                
                                // Call this class' methods to initialize the encryptor
                                //encryptor = new Encryptor(salt);//encryptor.salt

                                // Read the encrypted file as a byte array to be decrypted
                                byte[] decryptedFileBytes = encryptor.fileToBytes(encryptedFilePath[a], true);//inputFilePath[a]
                                
                                encryptor.bytesToFile(decryptedFileBytes, decryptedFilePath[a], false);
                            }
                        } else {
                            System.err.println("File " + f.getAbsolutePath() + " does not exist");
                            //continue; //not necessary, it's at the end of the line anyway
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error encrypting or decrypting file: " + e.getMessage());
            System.err.println("Error: " + e);
            e.printStackTrace();
            //throw new RuntimeException(); //not necessary, it's at the end of the execution method anyway
        }
    }
}