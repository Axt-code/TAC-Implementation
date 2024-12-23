// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import {G} from "../libraries/G.sol";

contract RequestCredential {
    uint256 internal o = G.GEN_ORDER;

    event SigReqBroadcast(
        address indexed client,
        uint256 sid,
        uint256 sigid,
        uint256[] attribute,
        uint256 no_of_private_attribute,
        uint256[2] B_dash,
        uint256[] k,
        uint256 c
    );

    function verify_pi_a(
        G.G1Point calldata _B_dash,
        uint256[] calldata kk,
        uint256 c,
        G.G1Point[] calldata _H
    ) private view returns (bool) {
        G.G1Point memory k1 = G.g1mul(_B_dash, o - c);

        G.G1Point memory k0 = G.g1mul(_H[0], kk[0]);

        for (uint256 i = 1; i < kk.length; i++) {
            k0 = G.g1add(k0, G.g1mul(_H[i], kk[i]));
        }

        G.G1Point memory k = G.g1add(k0, k1);

        uint256 c_dash = toChallenge(_B_dash, k, _H);
        c_dash = c_dash % o;
        return c == c_dash;
    }

    function toChallenge(
        G.G1Point memory B_dash,
        G.G1Point memory k,
        G.G1Point[] memory H
    ) public pure returns (uint256) {
        bytes memory result = new bytes(64 + H.length * 32);

        bytes32 _B_dash_b = G.G1_to_binary256(B_dash);

        for (uint256 i = 0; i < 32; i++) {
            result[i] = _B_dash_b[i];
        }

        bytes32 _k_b = G.G1_to_binary256(k);
        for (uint256 i = 0; i < 32; i++) {
            result[i + 32] = _k_b[i];
        }

        uint256 location = 64;
        for (uint256 i = 0; i < H.length; i++) {
            bytes32 X = G.G1_to_binary256(H[i]);
            for (uint256 j = 0; j < 32; j++) {
                result[j + location] = X[j];
            }
            location = location + 32;
        }

        bytes32 Chash = sha256(result);
        // emit debug_to_challenge(_B_dash_b, _k_b, result, Chash);
        return uint256(Chash);
    }

    function broadcastSigReq(
        uint256 sid,
        uint256 sigid,
        uint256[] calldata attribute,
        uint256 _no_of_private_attribute,
        G.G1Point calldata _B_dash,
        uint256[] calldata k,
        uint256 c,
        G.G1Point[] calldata _H
    ) external {
        if (verify_pi_a(_B_dash, k, c, _H)) {
            uint256[2] memory B_dash = [_B_dash.X, _B_dash.Y];
            emit SigReqBroadcast(
                msg.sender,
                sid,
                sigid,
                attribute,
                _no_of_private_attribute,
                B_dash,
                k,
                c
            );
        }
    }

}
