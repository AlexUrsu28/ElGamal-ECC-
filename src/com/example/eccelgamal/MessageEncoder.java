package com.example.eccelgamal;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Helper pentru encodarea unui BigInteger ca punct pe curbă și invers.
 *
 * Schema (educațională, nu pentru producție):
 *
 *  ENCODE (m -> M):
 *   - Alegem o constantă K (ex: 1000).
 *   - Construim coordonate candidate:
 *        X = m * K + i, pentru i = 0 .. MAX_TRIES
 *   - Transformăm X în bytes de lungime fixă (lungimea câmpului).
 *   - Încercăm să decodăm două variante de punct comprimat:
 *        0x02 || xBytes  (y par)
 *        0x03 || xBytes  (y impar)
 *   - Folosim primul punct valid (decodePoint nu aruncă excepție).
 *
 *  DECODE (M -> m):
 *   - Extragem coordonata X a punctului M.
 *   - Calculăm m = X / K.
 *
 * Atenție: schema e doar pentru proiect academic.
 */
public class MessageEncoder {

    private static final BigInteger K = BigInteger.valueOf(1000); // factor de scalare
    private static final int MAX_TRIES = 1000; // număr maxim de încercări pentru i

    /**
     * Encodează un mesaj m (BigInteger) într-un punct M pe curba dată.
     */
    public static ECPoint encode(BigInteger message, ECParameterSpec params) {
        ECCurve curve = params.getCurve();
        int fieldSize = curve.getFieldSize();       // mărimea câmpului în biți
        int byteLen = (fieldSize + 7) / 8;          // nr. de bytes necesari pentru coordonate

        // baza pentru X: X = m * K + i
        BigInteger baseX = message.multiply(K);

        for (int i = 0; i < MAX_TRIES; i++) {
            BigInteger x = baseX.add(BigInteger.valueOf(i));

            // transformăm x într-un array de bytes de lungime fixă
            byte[] xBytes = toFixedLength(x, byteLen);

            // încercăm varianta cu y par (prefix 0x02)
            byte[] compEven = new byte[1 + byteLen];
            compEven[0] = 0x02;
            System.arraycopy(xBytes, 0, compEven, 1, byteLen);

            try {
                ECPoint point = curve.decodePoint(compEven).normalize();
                // dacă nu aruncă excepție, avem punct valid
                return point;
            } catch (IllegalArgumentException e) {
                // nu e punct valid cu y par, încercăm y impar
            }

            // încercăm varianta cu y impar (prefix 0x03)
            byte[] compOdd = new byte[1 + byteLen];
            compOdd[0] = 0x03;
            System.arraycopy(xBytes, 0, compOdd, 1, byteLen);

            try {
                ECPoint point = curve.decodePoint(compOdd).normalize();
                return point;
            } catch (IllegalArgumentException e) {
                // nici această variantă nu e validă, trecem la i+1
            }
        }

        throw new IllegalStateException("Nu s-a putut encoda mesajul ca punct pe curba (MAX_TRIES depășit).");
    }

    /**
     * Decodează un punct M înapoi într-un BigInteger m, presupunând că
     * a fost encodat cu schema de mai sus (X = m * K + i).
     */
    public static BigInteger decode(ECPoint point, ECParameterSpec params) {
        // normalizăm punctul pentru a avea coordonate affine (x, y)
        ECPoint norm = point.normalize();
        BigInteger x = norm.getAffineXCoord().toBigInteger();

        // m = X / K (partea întreagă)
        return x.divide(K);
    }

    /**
     * Convertește un BigInteger într-un array de bytes de lungime fixă.
     * Dacă este prea scurt -> padding cu 0 la început.
     * Dacă este prea lung -> se taie octeții de semn din față.
     */
    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();

        if (raw.length == length) {
            return raw;
        } else if (raw.length > length) {
            // tăiem octeții din față în plus
            return Arrays.copyOfRange(raw, raw.length - length, raw.length);
        } else {
            // padding cu 0 la început
            byte[] result = new byte[length];
            System.arraycopy(raw, 0, result, length - raw.length, raw.length);
            return result;
        }
    }
}

