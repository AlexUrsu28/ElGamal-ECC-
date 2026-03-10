package com.example.eccelgamal;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Clasă utilitară pentru lucrul cu curbe eliptice folosind Bouncy Castle.
 * - încărcarea curbelor standard (ex. "secp256k1")
 * - generarea unui scalar aleator (pentru chei, k în ElGamal)
 * - acces la punctul generator G al curbei
 */
public class ECCUtils {

    private static final SecureRandom random = new SecureRandom();

    /**
     * Returnează parametrii pentru o curbă standard ECC (ex: "secp256k1", "secp256r1").
     */
    public static ECParameterSpec getCurveParameters(String curveName) {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
        if (params == null) {
            throw new IllegalArgumentException("Curba nu a fost găsită: " + curveName);
        }
        return params;
    }

    /**
     * Generează un scalar aleator în intervalul [1, n-1],
     * unde n este ordinul punctului generator G.
     * Acesta este folosit atât ca cheie privată x, cât și ca nonce k la criptare.
     */
    public static BigInteger generateRandomScalar(ECParameterSpec params) {
        BigInteger n = params.getN();
        BigInteger d;
        do {
            // generăm un număr cu aceeași lungime în biți ca n și îl reducem modulo n
            d = new BigInteger(n.bitLength(), random).mod(n);
        } while (d.equals(BigInteger.ZERO));
        return d;
    }

    /**
     * Returnează punctul generator G din parametrii curbei.
     */
    public static ECPoint getGenerator(ECParameterSpec params) {
        return params.getG();
    }
}

