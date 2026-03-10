package com.example.eccelgamal;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Implementare didactică a criptosistemului ElGamal pe curbe eliptice folosind Bouncy Castle.
 *
 * Parametrii:
 *  - curba este dată de ECParameterSpec (ex: secp256k1)
 *
 * Chei:
 *  - Cheie privată: x
 *  - Cheie publică: Q = xG
 *
 * Criptare (pentru un punct M pe curbă):
 *  1) Alegem k aleator în [1, n-1]
 *  2) C1 = kG
 *  3) C2 = M + kQ
 *
 * Decriptare:
 *  - M = C2 - xC1 = C2 + (-xC1)
 *  - deoarece xC1 = x(kG) = k(xG) = kQ.
 */
public class ElGamalECC {

    private final ECParameterSpec params;

    public ElGamalECC(ECParameterSpec params) {
        this.params = params;
    }

    /**
     * Generează o pereche de chei ElGamal pe curba dată:
     *  - x: scalar aleator
     *  - Q = xG: punct pe curba eliptică (cheie publică)
     */
    public ElGamalKeyPair generateKeyPair() {
        // x ∈ [1, n-1]
        BigInteger x = ECCUtils.generateRandomScalar(params);

        // Q = xG
        ECPoint G = params.getG();
        ECPoint Q = G.multiply(x).normalize();

        return new ElGamalKeyPair(x, Q);
    }

    /**
     * Criptează un punct M folosind cheia publică Q.
     *
     * Intrări:
     *  - M: punct pe curbă (mesajul deja encodat ca ECPoint)
     *  - publicKey: Q = xG
     *
     * Ieșire:
     *  - cifrul (C1, C2)
     */
    public ElGamalCiphertext encrypt(ECPoint M, ECPoint publicKey) {
        // k ∈ [1, n-1]
        BigInteger k = ECCUtils.generateRandomScalar(params);
        ECPoint G = params.getG();

        // C1 = kG
        ECPoint C1 = G.multiply(k).normalize();

        // kQ
        ECPoint kQ = publicKey.multiply(k).normalize();

        // C2 = M + kQ
        ECPoint C2 = M.add(kQ).normalize();

        return new ElGamalCiphertext(C1, C2);
    }

    /**
     * Decriptează un cifru (C1, C2) folosind cheia privată x.
     *
     *  xC1 = x(kG) = kQ
     *  M   = C2 - xC1 = C2 + (-xC1)
     */
    public ECPoint decrypt(ElGamalCiphertext ciphertext, BigInteger privateKey) {
        ECPoint C1 = ciphertext.getC1();
        ECPoint C2 = ciphertext.getC2();

        // xC1
        ECPoint xC1 = C1.multiply(privateKey).normalize();

        // -xC1
        ECPoint minusxC1 = xC1.negate().normalize();

        // M = C2 + (-xC1)
        return C2.add(minusxC1).normalize();
    }
}

