package com.example.eccelgamal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.Security;

/**
 * Demo complet pentru schema ElGamal pe curbe eliptice cu Bouncy Castle.
 *
 * Pași:
 *  1. Înregistrează provider-ul Bouncy Castle.
 *  2. Încarcă parametrii unei curbe standard (ex: "secp256k1").
 *  3. Generează perechea de chei (x, Q = xG).
 *  4. Alege un mesaj (BigInteger) și îl encodează într-un punct M.
 *  5. Criptează M cu ElGamal => (C1, C2).
 *  6. Decriptează (C1, C2) și recuperează M'.
 *  7. Decodează M' înapoi în BigInteger și verifică egalitatea cu mesajul inițial.
 */
public class ElGamalEccDemo {

    public static void main(String[] args) {
        // 1. Adăugăm provider-ul Bouncy Castle (clasic în Java pentru crypto extra)
        Security.addProvider(new BouncyCastleProvider());

        // 2. Alegem o curbă standard suportată de Bouncy Castle
        String curveName = "secp256k1"; // poți schimba în "secp256r1" etc.
        ECParameterSpec params = ECCUtils.getCurveParameters(curveName);

        System.out.println("Folosește curba: " + curveName);
        System.out.println("Dimensiune câmp (biți): " + params.getCurve().getFieldSize());

        // 3. Inițializăm schema ElGamal ECC cu această curbă
        ElGamalECC elGamal = new ElGamalECC(params);

        // 4. Generăm perechea de chei
        ElGamalKeyPair keyPair = elGamal.generateKeyPair();
        BigInteger priv = keyPair.getPrivateKey();
        ECPoint pub = keyPair.getPublicKey();

        System.out.println("Cheie privată x = " + priv.toString(16));
        System.out.println("Cheie publică Q = " + pub);

        // 5. Definim un mesaj ca BigInteger (în practică poate fi derivat din bytes/String)
        BigInteger message = new BigInteger("123456789"); // exemplu
        System.out.println("Mesaj original (BigInteger) = " + message);

        // 6. Encodăm mesajul într-un punct M pe curbă
        ECPoint M = MessageEncoder.encode(message, params);
        System.out.println("Punctul mesaj M = " + M);

        // 7. Criptăm punctul M cu cheia publică Q
        ElGamalCiphertext ciphertext = elGamal.encrypt(M, pub);
        System.out.println("Cifru C1 = " + ciphertext.getC1());
        System.out.println("Cifru C2 = " + ciphertext.getC2());

        // 8. Decriptăm cifrul folosind cheia privată x
        ECPoint decryptedPoint = elGamal.decrypt(ciphertext, priv);
        System.out.println("Punct decriptat M' = " + decryptedPoint);

        // 9. Decodează punctul înapoi în BigInteger
        BigInteger recoveredMessage = MessageEncoder.decode(decryptedPoint, params);
        System.out.println("Mesaj recuperat (BigInteger) = " + recoveredMessage);

        // 10. Verifică dacă mesajul inițial și cel recuperat sunt egale
        boolean ok = message.equals(recoveredMessage);
        System.out.println("Decriptare + decodare corectă? " + ok);
    }
}

