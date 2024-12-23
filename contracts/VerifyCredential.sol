// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import {G} from "../libraries/G.sol";

contract VerifyCredential {

    event SPOKBroadcast(
        address indexed client,
        uint256 sid,
        uint256 sigid,
        SPOKParams pi,
        G1Points points,
        uint256[] attribute,
        uint256 no_of_private_attribute
    );

    struct SPOKParams {
        uint256 c;
        uint256 re;
        uint256 rr2;
        uint256 rr3;
        uint256 rs_dash;
        uint256 _timestamp;
        uint256[] rm;
    }

    struct G1Points {
        uint256[2] A_dash;
        uint256[2] A_bar;
        uint256[2] d;
    }

    struct AwParams {
        uint256 re;
        uint256 rr2;
        G.G1Point A_dash;
        G.G1Point H0;
    }

    // Pack the variables into structs to reduce stack depth
    function toChallenge_spok(
        G.G1Point memory Aw,
        G.G1Point memory Bw,
        G.G1Point memory A_bar_d,
        G.G1Point[] memory H,
        uint256[] memory attribute,
        uint256 _timestamp
    ) public pure returns (uint256) {
        bytes memory result = getToChallengeBytes(Aw, Bw, A_bar_d, H, attribute, _timestamp);
        return uint256(sha256(result));
    }

    function getToChallengeBytes(
        G.G1Point memory Aw,
        G.G1Point memory Bw,
        G.G1Point memory A_bar_d,
        G.G1Point[] memory H,
        uint256[] memory attribute,
        uint256 _timestamp
    ) internal pure returns (bytes memory) {
        // Using a more efficient memory allocation strategy to optimize
        uint256 size = 192 + (H.length  + attribute.length) * 32;
        bytes memory result = new bytes(size);

        bytes32 X = G.G1_to_binary256(G.P1());
        for (uint256 i = 0; i < 32; i++) {
            result[i] = X[i];
        }

        X = G.G2_to_binary256(G.P2());
        for (uint256 i = 0; i < 32; i++) {
            result[32 + i] = X[i];
        }

        X = G.G1_to_binary256(Aw);
        for (uint256 i = 0; i < 32; i++) {
            result[64 + i] = X[i];
        }

        X = G.G1_to_binary256(Bw);
        for (uint256 i = 0; i < 32; i++) {
            result[96 + i] = X[i];
        }

        X = G.G1_to_binary256(A_bar_d);
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

        for (uint256 i = 0; i < attribute.length; i++) {
            X = bytes32(attribute[i]);
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

    // function copyBytes(bytes memory result, bytes32 src, uint256 startIndex) internal pure {
    //     for (uint256 i = 0; i < 32; i++) {
    //         result[startIndex + i] = src[i];
    //     }
    // }



    function verify_spok(
        G.G1Point[] memory _H,
        SPOKParams memory pi,
        G.G1Point memory A_dash,
        G.G1Point memory A_bar,
        G.G1Point memory d,
        uint256[] memory attribute,
        uint256 _no_of_private_attribute
    ) private view returns (bool) {
        G.G1Point memory A_bar_d = computeA_bar_d(A_bar, d);
        AwParams memory awParams = AwParams(pi.re, pi.rr2, A_dash, _H[0]);
        // G.G1Point memory Aw = computeAw(A_bar_d, pi.c, awParams);
        // G.G1Point memory Bw = computeBw(d, pi, _H, attribute, _no_of_private_attribute);
        
        // return verify_challenge(Aw, Bw, A_bar_d, _H, attribute, pi);
        return pi.c == toChallenge_spok(computeAw(A_bar_d, pi.c, awParams), computeBw(d, pi, _H, attribute, _no_of_private_attribute), A_bar_d, _H, attribute, pi._timestamp);
    }


    function computeA_bar_d(G.G1Point memory A_bar, G.G1Point memory d) public view returns (G.G1Point memory) {
        return G.g1add(A_bar, G.g1neg(G.g1mul(d, 1)));
    }

    function computeAw(
        G.G1Point memory A_bar_d,
        uint256 c,
        AwParams memory params
    ) public view returns (G.G1Point memory) {
        return G.g1add(
            G.g1mul(A_bar_d, c),
            G.g1add(G.g1neg(G.g1mul(params.A_dash, params.re)), G.g1mul(params.H0, params.rr2))
        );
    }

    function computeBw(
        G.G1Point memory d,
        SPOKParams memory pi,
        G.G1Point[] memory _H,
        uint256[] memory attribute,
        uint256 _no_of_private_attribute
    ) public view returns (G.G1Point memory) {
        G.G1Point memory term_2 = G.P1();
        for (uint256 i = 0; i < attribute.length; i++) {
            term_2 = G.g1add(term_2, G.g1mul(_H[i + 1 + _no_of_private_attribute], attribute[i]));
        }

        G.G1Point memory Bw = G.g1add(
            G.g1mul(term_2, pi.c),
            G.g1add(G.g1mul(d, pi.rr3), G.g1neg(G.g1mul(_H[0], pi.rs_dash)))
        );

        for (uint256 i = 0; i < _no_of_private_attribute; i++) {
            Bw = G.g1add(Bw, G.g1neg(G.g1mul(_H[i + 1], pi.rm[i])));
        }

        return Bw;
    }

    function broadcastSPOK(
        uint256 sid,
        uint256 sigid,
        G.G1Point[] memory _H,
        G.G2Point memory X,
        SPOKParams memory pi,
        G.G1Point memory A_dash,
        G.G1Point memory A_bar,
        G.G1Point memory d,
        uint256[] memory attribute,
        uint256 _no_of_private_attribute
    ) public {
        if (verifyCred(_H, X, pi, A_dash, A_bar, d, attribute, _no_of_private_attribute)) {
            emit SPOKBroadcast(msg.sender, sid, sigid, pi, G1Points([A_dash.X, A_dash.Y], [A_bar.X, A_bar.Y], [d.X, d.Y]), attribute, _no_of_private_attribute);
        }
    }

   
    function verifyCred(
        G.G1Point[] memory _H,
        G.G2Point memory X,
        SPOKParams memory pi,
        G.G1Point memory A_dash,
        G.G1Point memory A_bar,
        G.G1Point memory d,
        uint256[] memory attribute,
        uint256 _no_of_private_attribute
    ) private view returns (bool) {
        // Split verification steps to reduce stack depth
        bool spokVerified = verify_spok(_H, pi, A_dash, A_bar, d, attribute, _no_of_private_attribute);
        bool pairingVerified = verifyPairing(A_dash, X, A_bar);
        return spokVerified && pairingVerified;
    }

    function verifyPairing(
        G.G1Point memory A_dash,
        G.G2Point memory X,
        G.G1Point memory A_bar
    ) internal view returns (bool) {

        G.G1Point[] memory AA = new G.G1Point[](2);
        G.G2Point[] memory AB = new G.G2Point[](2);

        AA[0] = G.g1neg(A_dash);
        AB[0] = X;

        AA[1] = A_bar;
        AB[1] = G.P2();


        return G.pairing(AA, AB);
    }
}
