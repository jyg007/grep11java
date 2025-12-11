package com.ibm.crypto.grep11.grpc;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.protobuf.ByteString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class Example1 {

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

    private static final long CKM_VENDOR_DEFINED       =      0x80000000;
    private static final long CKM_IBM_ED25519_SHA512   =      CKM_VENDOR_DEFINED + 0x0001001c;
    private static final long CKM_ECDSA             =         0x00001041;


    // --- GRPC client ---
    private final CryptoGrpc.CryptoBlockingStub client;


    public Example1(String host, int port) {
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
    // + OIDs
    // ============================================================
    public static final String ED25519_OID = "1.3.101.112";

    private static final ASN1ObjectIdentifier OIDNamedCurveEd25519 =
            new ASN1ObjectIdentifier(ED25519_OID);
    private static final ASN1ObjectIdentifier OIDNamedCurveSecp256k1 =
            new ASN1ObjectIdentifier("1.3.132.0.10");
    private static final ASN1ObjectIdentifier OIDDilithiumHigh =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.1.6.5");


    // ============================================================
    // Enum for all key types
    // ============================================================
    public enum KeyType {
        ED25519,
        SECP256K1,
    }

public static class KeyPairBlob {
    public final ByteString pub;
    public final ByteString priv;

    public KeyPairBlob(ByteString pub, ByteString priv) {
        this.pub = pub;
        this.priv = priv;
    }
}

    // ============================================================
    // The main keypair generator
    // ============================================================
    public KeyPairBlob generate(KeyType type) throws IOException {

        Mechanism mech;
        GenerateKeyPairRequest request = null;

        switch (type) {

        // -----------------------------------------------------------------
        case ED25519:
            mech = Mechanism.newBuilder()
                    .setMechanism(CKM_EC_KEY_PAIR_GEN)
                    .build();

            request = GenerateKeyPairRequest.newBuilder()
                    .setMech(mech)

                    // --- Public Key Template ---
                    .putPubKeyTemplate(CKA_EC_PARAMS,
                            aB(OIDNamedCurveEd25519.getEncoded()))
                    .putPubKeyTemplate(CKA_VERIFY, aTF(true))

                    // --- Private Key Template ---
                    .putPrivKeyTemplate(CKA_SIGN,        aTF(true))
                    .putPrivKeyTemplate(CKA_EXTRACTABLE, aTF(false))

                    .build();
            break;

        // -----------------------------------------------------------------
        case SECP256K1:
            mech = Mechanism.newBuilder()
                    .setMechanism(CKM_EC_KEY_PAIR_GEN)
                    .build();

            request = GenerateKeyPairRequest.newBuilder()
                    .setMech(mech)

                    // --- Public Key Template ---
                    .putPubKeyTemplate(CKA_EC_PARAMS,
                            aB(OIDNamedCurveSecp256k1.getEncoded()))
                    .putPubKeyTemplate(CKA_VERIFY, aTF(true))

                    // --- Private Key Template ---
                    .putPrivKeyTemplate(CKA_SIGN,        aTF(true))
                    .putPrivKeyTemplate(CKA_DERIVE,      aTF(true))
                    .putPrivKeyTemplate(CKA_EXTRACTABLE, aTF(false))

                    .build();
            break;

        }

        // Send request
        GenerateKeyPairResponse response = client.generateKeyPair(request);
 
        ByteString privBlob = response.getPrivKey().getKeyBlobs(0);
        byte[] keyBytes = privBlob.toByteArray();

        // Convert to hex string
        StringBuilder sb = new StringBuilder();
        for (byte b : keyBytes) {
            sb.append(String.format("%02x", b));
        }
        System.out.println(sb.toString());
       
	ByteString pubBlob = response.getPubKey().getKeyBlobs(0);
        keyBytes = pubBlob.toByteArray();

        // Convert to hex string
        sb = new StringBuilder();
        for (byte b : keyBytes) {
            sb.append(String.format("%02x", b));
        }
        System.out.println(sb.toString());

	return new KeyPairBlob(pubBlob, privBlob);
    }


public byte[] sign(KeyType type, ByteString privKeyBlob, byte[] data) throws IOException {

    Mechanism mech;
    SignSingleRequest request = null;

    KeyBlob privKey = KeyBlob.newBuilder()
            .addKeyBlobs(privKeyBlob)
            .build();

    switch (type) {

    // =================================================================
    case ED25519:
        // EdDSA signs raw data directly
        mech = Mechanism.newBuilder()
                .setMechanism(CKM_IBM_ED25519_SHA512)
                .build();

        request = SignSingleRequest.newBuilder()
                .setMech(mech)
                .setPrivKey(privKey)
                .setData(ByteString.copyFrom(data))
                .build();
        break;

    // =================================================================
    case SECP256K1:
        // ECDSA signs a hash, so hash the data first
        byte[] digest;
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            digest = md.digest(data);
        } catch (Exception e) {
            throw new IOException("Failed to compute SHA-256 digest", e);
        }

        mech = Mechanism.newBuilder()
                .setMechanism(CKM_ECDSA)
                .build();

        request = SignSingleRequest.newBuilder()
                .setMech(mech)
                .setPrivKey(privKey)
                .setData(ByteString.copyFrom(digest))
                .build();
        break;

    } // end switch

    // =================================================================
    // Perform the signing operation
    // =================================================================
    SignSingleResponse response = client.signSingle(request);

    return response.getSignature().toByteArray();
}

private  boolean verify(
        ByteString signature,
        ByteString  pubKeyBlob,
        ByteString data,
        KeyType keyType
) {
    Mechanism mech= null;
    KeyBlob pubKey = KeyBlob.newBuilder()
        .addKeyBlobs(pubKeyBlob)
        .build();

    switch (keyType) {
        case ED25519:
            mech = Mechanism.newBuilder()
                .setMechanism(CKM_IBM_ED25519_SHA512)
                .build();
            break;
        case SECP256K1:
            mech = Mechanism.newBuilder()
                .setMechanism(CKM_ECDSA)
                .build();
            break;

        default:
            throw new RuntimeException("Unsupported key type for verify");
    }

    VerifySingleRequest request = VerifySingleRequest.newBuilder()
            .setMech(mech)
            .setPubKey(pubKey)
            .setData(data)
            .setSignature(signature)
            .build();

   try {
        VerifySingleResponse response = client.verifySingle(request);
        return true;  // verification succeeded
    } catch (io.grpc.StatusRuntimeException e) {
        // handle specific signature invalid exception if you want
        if (e.getMessage().contains("CKR_SIGNATURE_INVALID")) {
     //       System.out.println("Signature verification failed");
            return false;
        }
        // rethrow other gRPC exceptions if needed
        throw e;
    }
}


    // ============================================================
    // Main program test
    // ============================================================
    public static void main(String[] args) throws Exception {

        Example1 gen = new Example1("127.0.0.1", 9876);

        KeyPairBlob kp = gen.generate(KeyType.ED25519);
//        gen.generate(KeyType.SECP256K1);
//
     byte[] signature = gen.sign(
	    KeyType.ED25519,
    		kp.priv,               // privKeyBlob
    		"hello world".getBytes()
	);  
     	System.out.println("Signature (hex): " + toHex(signature));
     
     	boolean valid = gen.verify(
        	ByteString.copyFrom(signature),
	        kp.pub,
    	    ByteString.copyFrom("hello world".getBytes()),
        	KeyType.ED25519
     	);
	System.out.println("Is signature valid? " + valid);
     };
}

