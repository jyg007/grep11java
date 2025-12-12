package com.ibm.crypto.grep11.grpc;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.math.BigInteger;
import java.util.Arrays;

import com.google.protobuf.ByteString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class GenerateRSAKeyPair {

public static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder(data.length * 2);
    for (byte b : data) {
        sb.append(String.format("%02x", b));
    }
    return sb.toString();
}

    // Hardcoded PKCS#11 / EP11 constants
    private static final long CKM_AES_KEY_GEN = 0x1080;     // AES key generation
    private static final long CKA_CLASS = 0x00;        // key length in bytes
    private static final long CKA_TOKEN = 0x01;        // key length in bytes
    private static final long CKA_KEY_TYPE = 0x100;        // key length in bytes
    private static final long CKA_VALUE_LEN = 0x161;        // key length in bytes
    private static final long CKA_ENCRYPT = 0x104;        // key usable for encryption
    private static final long CKA_DECRYPT = 0x105;        // key usable for decryption
    private static final long CKA_WRAP = 0x106;        // key usable for decryption
    private static final long CKA_UNWRAP = 0x107;        // key usable for decryption
    private static final long CKA_EXTRACTABLE = 0x162;      // key extractable or not
    private static final long CKO_SECRET_KEY = 0x04;      // key extractable or not
    private static final long CKK_AES    =         0x0000001F ;      // key extractable or not
    private static final long CKA_SIGN      =         0x00000108;
    private static final long CKA_VERIFY     =        0x0000010A;
    private static final long CKA_DERIVE      =       0x0000010C;
    private static final long CKA_EC_PARAMS    =      0x00000180;
    private static final long CKM_EC_KEY_PAIR_GEN       =     0x00001040;
    private static final long   CKM_RSA_PKCS_KEY_PAIR_GEN  =    0x00000000;
    private static final long  CKA_MODULUS_BITS   =    0x00000121;
    private static final long  CKA_PUBLIC_EXPONENT =   0x00000122;
    private static final long CKM_RSA_PKCS_OAEP    =          0x00000009;
    private static final long CKA_PRIVATE   =        0x00000002;
    private static final long CKM_SHA512      =               0x00000270;
    private static final long CKG_MGF1_SHA512 = 0x00000004;

    // --- GRPC client ---
    private final CryptoGrpc.CryptoBlockingStub client;

    public GenerateRSAKeyPair(String host, int port) {
        ManagedChannel ch = ManagedChannelBuilder.forAddress(host, port)
                .usePlaintext()
                .build();
        client = CryptoGrpc.newBlockingStub(ch);
    }

    // ============================================================
    // Helper attribute builders
    // ============================================================
    private static AttributeValue aI(long v) {
        return AttributeValue.newBuilder().setAttributeI(v).build();
    }

    private static AttributeValue aTF(boolean v) {
        return AttributeValue.newBuilder().setAttributeTF(v).build();
    }

    private static AttributeValue aB(byte[] v) {
        return AttributeValue.newBuilder().setAttributeB(ByteString.copyFrom(v)).build();
    }

    // ============================================================
    // The main keypair generator
    // ============================================================
    public void generate() throws IOException {

        Mechanism mech;
        GenerateKeyPairRequest request = null;
	int publicExponent = 65537;
	int keySize = 4096;
	byte[] exponentBytes = BigInteger.valueOf(publicExponent).toByteArray();
	if (exponentBytes[0] == 0x00) {
	    exponentBytes = Arrays.copyOfRange(exponentBytes, 1, exponentBytes.length);
	}
        mech = Mechanism.newBuilder()
                 .setMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN)
                 .build();

            request = GenerateKeyPairRequest.newBuilder()
                    .setMech(mech)

                    // --- Public Key Template ---
                    .putPubKeyTemplate(CKA_WRAP, aTF(true))
                    .putPubKeyTemplate(CKA_ENCRYPT, aTF(true))
		    .putPubKeyTemplate(CKA_MODULUS_BITS, AttributeValue.newBuilder().setAttributeI(keySize).build())
		    .putPubKeyTemplate(CKA_PUBLIC_EXPONENT, AttributeValue.newBuilder().setAttributeB(ByteString.copyFrom(exponentBytes)).build())
                    // --- Private Key Template ---
                    .putPrivKeyTemplate(CKA_DECRYPT,        aTF(true))
                    .putPrivKeyTemplate(CKA_UNWRAP,        aTF(true))
                    .putPrivKeyTemplate(CKA_PRIVATE,        aTF(true))

                    .build();


        // Send request
        GenerateKeyPairResponse response = client.generateKeyPair(request);
 
        System.out.println("Priv Key: " + Example2.toHex(response.getPrivKey().toByteArray()));
        System.out.println("Pub Key: " + Example2.toHex(response.getPubKey().toByteArray()));

	return;
    }


    // ============================================================
    // Main program test
    // ============================================================
    public static void main(String[] args) throws Exception {

        GenerateRSAKeyPair gen = new GenerateRSAKeyPair("127.0.0.1", 9876);
        gen.generate();
    }
}

