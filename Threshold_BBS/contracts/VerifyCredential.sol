// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import {G} from "../libraries/G.sol";

contract VerifyCredential{

    event SPOKBroadcast(
        address indexed client,
        uint256 sid,
        uint256 sigid,
        SPOKParams pi,
        G1Points points,
        uint256[] public_attribute,
        uint256 total_attributes
    );

    struct SPOKParams {
        uint256 c;
        uint256 s;
        uint256 t;
        uint256[] u_i;
        uint256 _timestamp;
    }

    struct G1Points {
        uint256[2] A_bar;
        uint256[2] B_bar;
    }

    function broadcastSPOK(
        uint256 sid,
        uint256 sigid,
        G.G1Point[] memory _H,
        G.G2Point memory X,
        SPOKParams memory pi,
        G.G1Point memory A_bar,
        G.G1Point memory B_bar,
        uint256[] memory public_attribute,
        uint256 total_attributes
    ) public {
        if (verifyCred(_H, X, pi, A_bar, B_bar, public_attribute, total_attributes)) {
            emit SPOKBroadcast(msg.sender, sid, sigid, pi, G1Points([A_bar.X, A_bar.Y], [B_bar.X, B_bar.Y]), public_attribute, total_attributes);
        }
    }

    function verifyCred(
        G.G1Point[] memory _H,
        G.G2Point memory X,
        SPOKParams memory pi,
        G.G1Point memory A_bar,
        G.G1Point memory B_bar,
        uint256[] memory public_attribute,
        uint256 total_attributes
    ) private view returns (bool) {
        // Split verification steps to reduce stack depth
        bool spokVerified = verify_spok(_H, pi, A_bar, B_bar, public_attribute, total_attributes);
        require(spokVerified, "SPOK verification failed");

        // Verify Pairing
        bool pairingVerified = verifyPairing(A_bar, X, B_bar);
        require(pairingVerified, "Pairing verification failed");

        return spokVerified && pairingVerified;
    }


    function verify_spok(
        G.G1Point[] memory _H,
        SPOKParams memory pi,
        G.G1Point memory A_bar,
        G.G1Point memory B_bar,
        uint256[] memory public_attribute,
        uint256 total_attributes
    ) private view returns (bool) {

        uint256 no_of_private_attr = total_attributes - public_attribute.length;

        G.G1Point memory C_j_m = computeC_j_m(_H, public_attribute, no_of_private_attr, total_attributes);
      
        G.G1Point memory U = computeU(_H, pi, A_bar, B_bar, no_of_private_attr, C_j_m);

        return pi.c == toChallenge_spok(A_bar, B_bar, U, _H, public_attribute, pi._timestamp);
    }

    function computeC_j_m(
    G.G1Point[] memory _H, 
    uint256[] memory public_attribute, 
    uint256 no_of_private_attr, 
    uint256 total_attributes
    ) internal view returns (G.G1Point memory) {
        require(total_attributes >= no_of_private_attr, "Invalid attribute bounds");
        require(public_attribute.length == (total_attributes - no_of_private_attr), "Mismatched public attributes");

        G.G1Point memory result = G.P1(); 

        for (uint256 j = 0; j < public_attribute.length; j++) {
            // Compute corresponding index in _H
            uint256 i = no_of_private_attr + j;

            // Perform the EC multiplication and addition
            G.G1Point memory temp = G.g1mul(_H[i], public_attribute[j]);
            result = G.g1add(result, temp);
        }

        return result;
    }

    function computeU(
    G.G1Point[] memory _H,
    SPOKParams memory pi,
    G.G1Point memory A_bar,
    G.G1Point memory B_bar,
    uint256 no_of_private_attr,
    G.G1Point memory C_j_m
    ) internal view returns (G.G1Point memory){
            G.G1Point memory U1 = G.g1add(G.g1mul(A_bar, pi.t), G.g1neg(G.g1mul(B_bar, pi.c)));
            G.G1Point memory U2 = computeU2(C_j_m, pi.s, _H, pi.u_i, no_of_private_attr);
            return G.g1add(U1, U2);
    }

    function computeU2(
    G.G1Point memory C_j_m,
    uint256 s,
    G.G1Point[] memory _H,
    uint256[] memory u_i,
    uint256 no_of_private_attr
) internal view returns (G.G1Point memory) {
    require(no_of_private_attr <= _H.length, "Invalid attribute count");
    require(u_i.length == no_of_private_attr, "Mismatched private attributes");

    // Perform the scalar multiplication of C_j_m with s
    G.G1Point memory result = G.g1mul(C_j_m, s);

    // Loop to compute the summation of H[i] * u_i[i]
    for (uint256 i = 0; i < no_of_private_attr; i++) {
        G.G1Point memory temp = G.g1mul(_H[i], u_i[i]);
        result = G.g1add(result, temp);
    }

    return result;
}

    // Pack the variables into structs to reduce stack depth
    function toChallenge_spok(
        G.G1Point memory A_bar,
        G.G1Point memory B_bar,
        G.G1Point memory U,
        G.G1Point[] memory H,
        uint256[] memory public_attribute,
        uint256 _timestamp
    ) public pure returns (uint256) {
        bytes memory result = getToChallengeBytes(A_bar, B_bar, U, H, public_attribute, _timestamp);
        return uint256(sha256(result));
    }

    function getToChallengeBytes(
        G.G1Point memory A_bar,
        G.G1Point memory B_bar,
        G.G1Point memory U,
        G.G1Point[] memory H,
        uint256[] memory public_attribute,
        uint256 _timestamp
    ) internal pure returns (bytes memory) {
        // Using a more efficient memory allocation strategy to optimize
        uint256 size = 192 + (H.length  + public_attribute.length) * 32;
        bytes memory result = new bytes(size);

        bytes32 X = G.G1_to_binary256(G.P1());
        for (uint256 i = 0; i < 32; i++) {
            result[i] = X[i];
        }

        X = G.G2_to_binary256(G.P2());
        for (uint256 i = 0; i < 32; i++) {
            result[32 + i] = X[i];
        }

        X = G.G1_to_binary256(A_bar);
        for (uint256 i = 0; i < 32; i++) {
            result[64 + i] = X[i];
        }

        X = G.G1_to_binary256(B_bar);
        for (uint256 i = 0; i < 32; i++) {
            result[96 + i] = X[i];
        }

        X = G.G1_to_binary256(U);
        for (uint256 i = 0; i < 32; i++) {
            result[128 + i] = X[i];
        }

        uint256 location = 160;
        for (uint256 i = 0; i < H.length; i++) {
            X = G.G1_to_binary256(H[i]);
            for (uint256 j = 0; j < 32; j++) {
                result[location + j] = X[j];
            }
            location += 32;
        }

        for (uint256 i = 0; i < public_attribute.length; i++) {
            X = bytes32(public_attribute[i]);
            for (uint256 j = 0; j < 32; j++) {
                result[location + j] = X[j];
            }
            location += 32;
        }

        X = bytes32(_timestamp);
        for (uint256 i = 0; i < 32; i++) {
            result[location + i] = X[i];
        }

        return result;
    }

    function verifyPairing(
        G.G1Point memory A_bar,
        G.G2Point memory X,
        G.G1Point memory B_bar
    ) internal view returns (bool) {

        G.G1Point[] memory AA = new G.G1Point[](2);
        G.G2Point[] memory AB = new G.G2Point[](2);

        AA[0] = G.g1neg(A_bar);
        AB[0] = X;

        AA[1] = B_bar;
        AB[1] = G.P2();

        return G.pairing(AA, AB);
    }
}