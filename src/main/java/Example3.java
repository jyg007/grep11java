package com.ibm.crypto.grep11.grpc;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.math.BigInteger;
import com.google.protobuf.ByteString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
//import java.security.SecureRandom;
import java.util.Arrays;
import java.io.ByteArrayInputStream;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class Example3 {

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
    private static final long  CKM_AES_CBC_PAD      =          0x00001085;
    private static final long   CKK_EC     =         0x00000003;
    private static final long   CKM_RSA_PKCS_KEY_PAIR_GEN  =    0x00000000;
    private static final long  CKA_MODULUS_BITS   =    0x00000121;
    private static final long  CKA_PUBLIC_EXPONENT =   0x00000122;
    private static final long CKM_RSA_PKCS_OAEP    =          0x00000009;
    private static final long CKA_PRIVATE   =        0x00000002;
    private static final long CKM_SHA512      =               0x00000270;
    private static final long CKG_MGF1_SHA512 = 0x00000004;
    private static final long CKM_SHA256      =               0x00000250;
    private static final long CKG_MGF1_SHA256 = 0x00000002;

    // --- GRPC client ---
    private final CryptoGrpc.CryptoBlockingStub client;

    public Example3(String host, int port) {
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
    public KeyPairBlob generateKeyPair(KeyType type) throws IOException {

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
                    .putPrivKeyTemplate(CKA_EXTRACTABLE, aTF(true))  //ONLY FOR THE EXAMPLE

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
                    .putPubKeyTemplate(CKA_EC_PARAMS, aB(OIDNamedCurveSecp256k1.getEncoded()))
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
 
	return new KeyPairBlob(response.getPubKey().getKeyBlobs(0),response.getPrivKey().getKeyBlobs(0));
    }

public ByteString generateKey() throws IOException {
    // Define the AES key mechanism
    Mechanism mechanism = Mechanism.newBuilder()
            .setMechanism(CKM_AES_KEY_GEN)
            .build();

    // Build AES key template (256-bit)
    GenerateKeyRequest request = GenerateKeyRequest.newBuilder()
            .setMech(mechanism)
            .putTemplate(CKA_VALUE_LEN, AttributeValue.newBuilder().setAttributeI(32).build()) // 32 bytes = 256 bits
            .putTemplate(CKA_ENCRYPT, AttributeValue.newBuilder().setAttributeTF(true).build())
            .putTemplate(CKA_WRAP, AttributeValue.newBuilder().setAttributeTF(true).build())
            .putTemplate(CKA_UNWRAP, AttributeValue.newBuilder().setAttributeTF(true).build())
            .putTemplate(CKA_DECRYPT, AttributeValue.newBuilder().setAttributeTF(true).build())
            .putTemplate(CKA_EXTRACTABLE, AttributeValue.newBuilder().setAttributeTF(true).build())  //ONLY FOR THE UNWRAP EXAMPLE !!!!!
            .build();

    // Generate AES key
    GenerateKeyResponse response = client.generateKey(request);

    return response.getKey().getKeyBlobs(0);
}

    public KeyPairBlob generateRSAKeyPair() throws IOException {

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
 
	return new KeyPairBlob(response.getPubKey().getKeyBlobs(0),response.getPrivKey().getKeyBlobs(0));
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

    VerifySingleRequest request = null;
    switch (keyType) {
        case ED25519:
            mech = Mechanism.newBuilder()
                .setMechanism(CKM_IBM_ED25519_SHA512)
                .build();
            request = VerifySingleRequest.newBuilder().setMech(mech).setPubKey(pubKey).setData(data).setSignature(signature).build();
            break;
        case SECP256K1:
            mech = Mechanism.newBuilder()
                .setMechanism(CKM_ECDSA)
                .build();
            byte[] digest;
            try {
                    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                    digest = md.digest(data.toByteArray());
            } catch (Exception e) {
                    throw new RuntimeException("Failed to compute SHA-256 digest", e); 
            }
            request = VerifySingleRequest.newBuilder().setMech(mech).setPubKey(pubKey).setData(ByteString.copyFrom(digest)).setSignature(signature).build();
            break;

        default:
            throw new RuntimeException("Unsupported key type for verify");
    }   


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


public String  parseSPKI(ByteString spkiBytes) throws IOException {
        byte[] data = spkiBytes.toByteArray();

        // Parse DER-encoded ASN.1 structure
        ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(data));
        ASN1Primitive spki = ais.readObject(); // parses the first ASN.1 object
        ais.close();

        // Calculate "rest" like in Go (remaining bytes after first ASN.1 object)
        int spkiLen = spki.getEncoded().length;
        return toHex(Arrays.copyOfRange(data, 0, spkiLen));
    }

public ByteString RSAwrapKey(ByteString kekKey, ByteString keyToWrap) throws IOException {

        // KEK KeyBlob
        KeyBlob kekBlob = KeyBlob.newBuilder()
                .addKeyBlobs(kekKey)
                .build();

        // Key to wrap
        KeyBlob keyBlob = KeyBlob.newBuilder()
                .addKeyBlobs(keyToWrap)
                .build();

	RSAOAEPParm oaep = RSAOAEPParm.newBuilder()
	    // Hash algorithm: CKM_SHA256
	    .setHashMech(CKM_SHA256)                          
            .setMgfValue((int)CKG_MGF1_SHA256)  // raw numeric value for MGF
	    .setEncodingParmTypeValue(0)
	    .setEncodingParm(ByteString.EMPTY)
	    //.setMgf(RSAOAEPParm.Mask.CkgMgf1Sha256)
    	    .build();

        Mechanism mech = Mechanism.newBuilder()
                .setMechanism(CKM_RSA_PKCS_OAEP)
		.setRSAOAEPParameter(oaep)
                .build();

        // WrapKeyRequest
        WrapKeyRequest request = WrapKeyRequest.newBuilder()
                .setMech(mech)
                .setKeK(kekBlob)
                .setKey(keyBlob)
                .build();

        // Call gRPC stub
        WrapKeyResponse response;
        try {
            response = client.wrapKey(request);
        } catch (io.grpc.StatusRuntimeException e) {
            throw new IOException("Wrap key failed: " + e.getMessage(), e);
        }

        // Return the wrapped key bytes
        return response.getWrapped();
    }


//*******************************************************************************
//*******************************************************************************
	public static class UnwrappedKey {
	    public final ByteString key;
	    public final ByteString checksum;

	    public UnwrappedKey(ByteString key, ByteString checksum) {
        	this.key = key;
	        this.checksum = checksum;
	    }
	}

	public UnwrappedKey RSAunwrapKey(
        	ByteString kekBlob,         // the unwrapping key (AES key usually)
	        ByteString wrappedBlob     // encrypted/wrapped private key
	) {


        RSAOAEPParm oaep = RSAOAEPParm.newBuilder()
            // Hash algorithm: CKM_SHA256
            .setHashMech(CKM_SHA256)
            .setMgfValue((int)CKG_MGF1_SHA256)  // raw numeric value for MGF
        //    .setEncodingParmTypeValue(0)  
          //  .setEncodingParm(ByteString.EMPTY)
            .build();

        Mechanism mech = Mechanism.newBuilder()
                .setMechanism(CKM_RSA_PKCS_OAEP)
                .setRSAOAEPParameter(oaep)
                .build();


	 KeyBlob kek = KeyBlob.newBuilder()
        	.addKeyBlobs(kekBlob)
	        .build();

	UnwrapKeyRequest request = UnwrapKeyRequest.newBuilder()
             	.setMech(mech)
  		.setKeK(kek)
        	.setWrapped(wrappedBlob)
                .putTemplate(CKA_VALUE_LEN, AttributeValue.newBuilder().setAttributeI(32).build()) // 32 bytes = 256 bits
            	.putTemplate(CKA_WRAP, AttributeValue.newBuilder().setAttributeTF(true).build())
            	.putTemplate(CKA_ENCRYPT, AttributeValue.newBuilder().setAttributeTF(true).build())
            	.putTemplate(CKA_DECRYPT, AttributeValue.newBuilder().setAttributeTF(true).build())
            	.putTemplate(CKA_UNWRAP, AttributeValue.newBuilder().setAttributeTF(true).build())
            	.putTemplate(CKA_EXTRACTABLE, AttributeValue.newBuilder().setAttributeTF(false).build())
		.putTemplate(CKA_CLASS, AttributeValue.newBuilder().setAttributeI(CKO_SECRET_KEY).build())
        	.putTemplate(CKA_KEY_TYPE, AttributeValue.newBuilder().setAttributeI(CKK_AES).build())
            	.build();   

	 // HSM call
	 UnwrapKeyResponse response = client.unwrapKey(request);

	 return new UnwrappedKey(response.getUnwrapped().getKeyBlobs(0),response.getCheckSum());
	}

    // ============================================================
    // Main program test
    // ============================================================
    public static void main(String[] args) throws Exception {

        Example3 gen = new Example3("127.0.0.1", 9876);

        KeyPairBlob kp = gen.generateRSAKeyPair();
        ByteString k =  gen.generateKey();

	System.out.println("AES Key: " + Example3.toHex(k.toByteArray()));
	System.out.println("Private Key: " + Example3.toHex(kp.priv.toByteArray()));
	System.out.println("Public Key: " + Example3.toHex(kp.pub.toByteArray()));

        ByteString wrappedKey = gen.RSAwrapKey(kp.pub,k);
        System.out.println();       
	System.out.println("Wrapped Key: " + Example3.toHex(wrappedKey.toByteArray()));
        UnwrappedKey unwrappedKey = gen.RSAunwrapKey(kp.priv,wrappedKey);
        System.out.println();       
	System.out.println("Unwrapped Key:      " + Example3.toHex(unwrappedKey.key.toByteArray()));
	System.out.println("Unwrapped checksum: " + Example3.toHex(unwrappedKey.checksum.toByteArray()));
//
     };
}

