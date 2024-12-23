// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;
import {G} from "../libraries/G.sol";

contract IssueCredential{
   
    event PartialCredential(
        address indexed client,
        uint256[2] h, 
        uint256[2] t,
        uint256[2][] g1_B, 
        uint256[4] A, 
        uint256[4][] B,
        uint256 issuer_id
    );

    // Function for partial credential issuance
    function issuePartialCredential(
        uint256[2] memory h, 
        uint256[2] memory t,
        G.G2Point memory _A,
        G.G2Point[] memory _B, 
        G.G1Point[] memory _g1_B,
        uint256 issuer_id

    ) public {  
        uint256[2][] memory g1_B = new uint256[2][](_g1_B.length);
        uint256[4] memory A = [_A.X[0], _A.X[1],_A.Y[0], _A.Y[1]];      
        uint256[4][] memory B = new uint256[4][](_B.length);
        for (uint256 i = 0; i < _g1_B.length; i++) {
            g1_B[i] = [_g1_B[i].X, _g1_B[i].Y];
        }
        for (uint256 i = 0; i < _B.length; i++) {
             B[i] = [_B[i].X[0], _B[i].X[1], _B[i].Y[0], _B[i].Y[1]];
        }
        uint256 issuer_index = issuer_id;
        emit PartialCredential(msg.sender, h, t, g1_B, A, B,issuer_index);
    }

   

}
