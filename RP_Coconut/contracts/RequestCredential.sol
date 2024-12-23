
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import {G} from "../libraries/G.sol";

contract RequestCredential {

        struct IssueProof {
        uint256 c;
        uint256 rr;
        uint256[] ros;
        uint256[] rm;
    }
    event emitRequest(address sender, uint256[2] cm, uint256[2][] commitments, string[] public_m);

    function ToChallengeIssue(G.G1Point memory cm, G.G1Point memory h, G.G1Point memory Bw, G.G1Point[] memory hs, G.G1Point[] memory Aw)
                                        internal pure returns (uint256)
     {
        bytes memory Cstring = new bytes(160 + (hs.length + Aw.length) * 32);
        bytes32 X = G.G1_to_binary256(G.P1());
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i] = X[i];
        }
        X = G.G2_to_binary256(G.P2());
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i+32] = X[i];
        }
        X = G.G1_to_binary256(cm);
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i+64] = X[i];
        }
        X = G.G1_to_binary256(h);
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i+96] = X[i];
        }
        X = G.G1_to_binary256(Bw);
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i+128] = X[i];
        }
        
        uint256 location = 160;
        for(uint256 i=0; i < hs.length; i++) {
            X = G.G1_to_binary256(hs[i]);
            for (uint256 j=0; j < 32 ; j++) {
                Cstring[j+location] = X[j];
            }
            location = location + 32;
        }
        for(uint256 i=0; i< Aw.length; i++){
            X = G.G1_to_binary256(Aw[i]);
            for (uint256 j=0; j < 32 ; j++) {
                Cstring[j+location] = X[j];
            }
            location = location + 32;
        }

        bytes32 Chash =  sha256(Cstring);
        return uint256(Chash);
    }

    function calculate_Aw( G.G1Point[] memory commitments, G.G1Point memory cm, IssueProof memory proof) private view returns (G.G1Point[] memory) {
        uint256[] memory ros = proof.ros;
        G.G1Point[] memory Aw = new G.G1Point[](ros.length);
        uint256[] memory rm = proof.rm;
        G.G1Point memory h = G.HashToPoint(uint256(G.G1_to_binary256(cm)));
        for(uint256 i=0; i < ros.length; i++) {
            Aw[i] = G.g1add(G.g1mul(commitments[i], proof.c), G.g1add(G.g1mul(G.P1(), ros[i]), G.g1mul(h, rm[i])));
        }
        return Aw;
    }

    function calculate_Bw( G.G1Point memory cm, IssueProof memory proof,G.G1Point[] memory _H) private view returns (G.G1Point memory) {
        uint256 c = proof.c;
        uint256 rr = proof.rr;
        uint256[] memory rm = proof.rm;
        G.G1Point[] memory hs = _H;
        G.G1Point memory Bw = G.g1add(G.g1mul(cm, c), G.g1mul(G.P1(), rr));
        for(uint256 i=0; i< rm.length; i++) {
            Bw = G.g1add(Bw, G.g1mul(hs[i], rm[i]));
        }
        return Bw;
    }

    function check_issue_proof( IssueProof memory proof, G.G1Point memory cm, G.G1Point[] memory commitments, string[] memory public_m, G.G1Point[] memory _H) private view returns (bool) {
        G.G1Point[] memory Aw = calculate_Aw( commitments, cm, proof);
        G.G1Point memory Bw = calculate_Bw(cm, proof, _H);
        return (proof.c == ToChallengeIssue(cm, G.HashToPoint(uint256(G.G1_to_binary256(cm))), Bw, _H, Aw));
    }

    function logging(address sender, G.G1Point memory cm, G.G1Point[] memory commitments, string[] memory public_m) private {
        uint256[2] memory commitment = [cm.X, cm.Y];
        uint256[2][] memory X = new uint256[2][](commitments.length);
        for (uint256 i=0;i<commitments.length;i++) {
            X[i][0] = commitments[i].X;
            X[i][1] = commitments[i].Y;
        }
        emit emitRequest(sender, commitment, X, public_m);
    }
    
    function RequestCred( G.G1Point memory cm, G.G1Point[] memory commitments, IssueProof memory iproof, string[] memory public_m, G.G1Point[] memory _H) public {
        require(check_issue_proof( iproof, cm, commitments, public_m, _H), "issuance ZKPoK verification failed");
        logging(msg.sender, cm, commitments, public_m);
    } 

}

    