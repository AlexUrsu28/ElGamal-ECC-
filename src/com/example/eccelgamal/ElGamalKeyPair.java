package com.example.eccelgamal;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Structură simplă pentru o pereche de chei ElGamal pe curbe eliptice:
 *  - privateKey = x
 *  - publicKey  = Q = xG
 */
public class ElGamalKeyPair {

    private final BigInteger privateKey; // x
    private final ECPoint publicKey;     // Q = xG

    public ElGamalKeyPair(BigInteger privateKey, ECPoint publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }
}

