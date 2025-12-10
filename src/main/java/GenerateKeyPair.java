package com.ibm.crypto.grep11.grpc;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.protobuf.ByteString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class GenerateKeyPair {
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


    // --- GRPC client ---
    private final CryptoGrpc.CryptoBlockingStub client;

    public GenerateKeyPair(String host, int port) {
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

    // ============================================================
    // The main keypair generator
    // ============================================================
    public void generate(KeyType type) throws IOException {

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
 
        ByteString keyBlob = response.getPrivKey().getKeyBlobs(0);
        byte[] keyBytes = keyBlob.toByteArray();

        // Convert to hex string
        StringBuilder sb = new StringBuilder();
        for (byte b : keyBytes) {
            sb.append(String.format("%02x", b));
        }
        System.out.println(sb.toString());
       
	 keyBlob = response.getPubKey().getKeyBlobs(0);
        keyBytes = keyBlob.toByteArray();

        // Convert to hex string
        sb = new StringBuilder();
        for (byte b : keyBytes) {
            sb.append(String.format("%02x", b));
        }
        System.out.println(sb.toString());
	return;
    }


    // ============================================================
    // Main program test
    // ============================================================
    public static void main(String[] args) throws Exception {

        GenerateKeyPair gen = new GenerateKeyPair("127.0.0.1", 9876);

        gen.generate(KeyType.ED25519);
        gen.generate(KeyType.SECP256K1);
    }
}

