package com.ibm.crypto.grep11.grpc;

import com.google.protobuf.ByteString;
import com.ibm.crypto.grep11.grpc.AttributeValue;
import com.ibm.crypto.grep11.grpc.CryptoGrpc;
import com.ibm.crypto.grep11.grpc.CryptoGrpc.CryptoBlockingStub;
import com.ibm.crypto.grep11.grpc.GenerateKeyRequest;
import com.ibm.crypto.grep11.grpc.GenerateKeyResponse;
import com.ibm.crypto.grep11.grpc.Mechanism;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class GenerateAESKey {

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

    public static void main(String[] args) throws Exception {
/*
        if (args.length < 2) {
            System.err.println("Usage: GenerateAESKey <hsm-host> <hsm-port>");
            System.exit(1);
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
*/
        // Connect to HSM gRPC server
        ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost",9876 )
                .usePlaintext() // or use TLS if your HSM requires it
                .build();
        CryptoGrpc.CryptoBlockingStub stub = CryptoGrpc.newBlockingStub(channel);

        // Build AES mechanism
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
                .putTemplate(CKA_EXTRACTABLE, AttributeValue.newBuilder().setAttributeTF(false).build())
		.build();

        // Generate AES key
        GenerateKeyResponse response = stub.generateKey(request);

        System.out.println("AES key generated successfully.");
        //System.out.println("Key handle: " + response.getKey());
	// Get the byte array
	ByteString keyBlob = response.getKey().getKeyBlobs(0);
	byte[] keyBytes = keyBlob.toByteArray();

	// Convert to hex string
	StringBuilder sb = new StringBuilder();
	for (byte b : keyBytes) {
	    sb.append(String.format("%02x", b));
	}
	System.out.println(sb.toString());
       	channel.shutdownNow();
    }
}

