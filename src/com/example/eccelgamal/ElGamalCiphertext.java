package com.example.eccelgamal;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Structură pentru un cifru ElGamal pe curbe eliptice:
 *  - C1 = kG
 *  - C2 = M + kQ
 */
public class ElGamalCiphertext {

    private final ECPoint c1;
    private final ECPoint c2;

    public ElGamalCiphertext(ECPoint c1, ECPoint c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    public ECPoint getC1() {
        return c1;
    }

    public ECPoint getC2() {
        return c2;
    }

    @Override
    public String toString() {
        return "ElGamalCiphertext{" +
                "C1=" + c1 +
                ", C2=" + c2 +
                '}';
    }
}

