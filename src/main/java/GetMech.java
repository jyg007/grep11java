package com.ibm.crypto.grep11.grpc;

import com.ibm.crypto.grep11.grpc.CryptoGrpc;
import com.ibm.crypto.grep11.grpc.GetMechanismListRequest;
import com.ibm.crypto.grep11.grpc.GetMechanismListResponse;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class GetMech {

    public static void main(String[] args) {
        // Connect to gRPC server (no TLS)
        ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 9876)
                                                      .usePlaintext() // no TLS
                                                      .build();

        CryptoGrpc.CryptoBlockingStub stub = CryptoGrpc.newBlockingStub(channel);

        // Build empty request
        GetMechanismListRequest request = GetMechanismListRequest.newBuilder().build();

        // Call the RPC
        GetMechanismListResponse response = stub.getMechanismList(request);

        // Loop through mechanisms
        for (long mech : response.getMechsList()) {
            System.out.println("Mechanism: " + mech);
        }

        channel.shutdown();
    }
}

