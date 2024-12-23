// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import {G} from "../libraries/G.sol";

contract IssueCredential {
    // mapping(uint256 => G.G1Point[]) public r_i;

    // Event to broadcast partial credential issuance
    event PartialCredential(
        address indexed client,
        uint256 sid,
        uint256 sigid,
        uint256 issuer_id,
        uint256 e,
        uint256 s,
        uint u_i,
        uint256[2] R_i,
        uint256[2] B_lemda,
        string pk_i
    );

    // Function for partial credential issuance
    function issuePartialCredential(
        uint256 sid,
        uint256 sigid,
        uint256 issuer_id,
        uint256 e,
        uint256 s,
        uint u_i,
        G.G1Point memory R_i,
        G.G1Point memory B_lemda,
        string memory pk_i
    ) public {
        uint256[2] memory _R_i = [R_i.X, R_i.Y];
        uint256[2] memory _B_lemda = [B_lemda.X, B_lemda.Y];

        emit PartialCredential(msg.sender, sid, sigid, issuer_id, e, s, u_i, _R_i, _B_lemda, pk_i);
    }
}
