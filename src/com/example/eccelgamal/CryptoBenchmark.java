package com.example.eccelgamal;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class CryptoBenchmark {

    private static final int ITERATIONS = 1000;

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        System.out.println("=== Crypto Benchmark ===");
        System.out.println("Iterations: " + ITERATIONS);
        System.out.println();

        benchmarkElGamalECC();
        benchmarkRSA();
        benchmarkSignatures();
    }

    /* ============================================================
       ElGamal pe Curbe Eliptice
       ============================================================ */
    private static void benchmarkElGamalECC() {

        ECParameterSpec params = ECCUtils.getCurveParameters("secp256k1");
        ElGamalECC ecc = new ElGamalECC(params);
        ElGamalKeyPair keyPair = ecc.generateKeyPair();

        BigInteger message = new BigInteger("123456789");
        ECPoint M = MessageEncoder.encode(message, params);

        long encStart = System.nanoTime();
        ElGamalCiphertext ct = null;
        for (int i = 0; i < ITERATIONS; i++) {
            ct = ecc.encrypt(M, keyPair.getPublicKey());
        }
        long encEnd = System.nanoTime();

        long decStart = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            ecc.decrypt(ct, keyPair.getPrivateKey());
        }
        long decEnd = System.nanoTime();

        System.out.println("[ElGamal ECC]");
        System.out.printf("Encryption avg: %.3f ms%n",
                (encEnd - encStart) / 1e6 / ITERATIONS);
        System.out.printf("Decryption avg: %.3f ms%n",
                (decEnd - decStart) / 1e6 / ITERATIONS);
        System.out.println();
    }

    /* ============================================================
       RSA Encryption / Decryption
       ============================================================ */
    private static void benchmarkRSA() throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA");

        byte[] message = "HelloCrypto".getBytes();

        long encStart = System.nanoTime();
        byte[] cipherText = null;
        for (int i = 0; i < ITERATIONS; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            cipherText = cipher.doFinal(message);
        }
        long encEnd = System.nanoTime();

        long decStart = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            cipher.doFinal(cipherText);
        }
        long decEnd = System.nanoTime();

        System.out.println("[RSA 2048]");
        System.out.printf("Encryption avg: %.3f ms%n",
                (encEnd - encStart) / 1e6 / ITERATIONS);
        System.out.printf("Decryption avg: %.3f ms%n",
                (decEnd - decStart) / 1e6 / ITERATIONS);
        System.out.println();
    }

    /* ============================================================
       Digital Signatures: ECDSA vs RSA vs DSA
       ============================================================ */
    private static void benchmarkSignatures() throws Exception {

        System.out.println("[Digital Signatures]");
        byte[] data = "HelloSignature".getBytes();

        benchmarkSignature("SHA256withECDSA", "EC", "secp256r1", data);
        benchmarkSignature("SHA256withRSA", "RSA", 2048, data);
        benchmarkSignature("SHA256withDSA", "DSA", 2048, data);

        System.out.println();
    }

    private static void benchmarkSignature(
            String algorithm,
            String keyAlg,
            Object keyParam,
            byte[] data) throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg, "BC");

        if (keyParam instanceof String) {
            kpg.initialize(new ECGenParameterSpec((String) keyParam));
        } else {
            kpg.initialize((int) keyParam);
        }

        KeyPair kp = kpg.generateKeyPair();
        Signature sig = Signature.getInstance(algorithm, "BC");

        long signStart = System.nanoTime();
        byte[] signature = null;
        for (int i = 0; i < ITERATIONS; i++) {
            sig.initSign(kp.getPrivate());
            sig.update(data);
            signature = sig.sign();
        }
        long signEnd = System.nanoTime();

        long verifyStart = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            sig.initVerify(kp.getPublic());
            sig.update(data);
            sig.verify(signature);
        }
        long verifyEnd = System.nanoTime();

        System.out.printf("[%s]%n", algorithm);
        System.out.printf("Sign avg: %.3f ms%n",
                (signEnd - signStart) / 1e6 / ITERATIONS);
        System.out.printf("Verify avg: %.3f ms%n",
                (verifyEnd - verifyStart) / 1e6 / ITERATIONS);
    }
}

