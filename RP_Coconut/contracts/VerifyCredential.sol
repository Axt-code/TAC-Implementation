
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import {G} from "../libraries/G.sol";

contract VerifyCredential {

    struct Theta {
        G.G2Point kappa;
        G.G1Point nu;
        G.G1Point[2] sigma;
        Proof proof;
    }
   
    struct Proof {
        uint256 c;
        uint256[] rm;
        uint256 rt;
    }
    event emitVerify( uint256[4] credential, string[] public_m);
    
   function VerifyCred(Theta memory theta, G.G1Point[] memory hs, G.G2Point memory alpha, G.G2Point[] memory beta, string[] memory public_m, G.G2Point memory Aw, uint256 _timestamp) public {
   if (verify_pi_v([theta.sigma[0], theta.nu], [Aw, theta.kappa], theta.proof,hs, alpha, beta, _timestamp))
   {
    G.G1Point[] memory coord1 = new G.G1Point[](2);
    G.G2Point[] memory coord2 = new G.G2Point[](2);
    coord1[0] = theta.sigma[0];
    coord1[1] = G.g1neg(G.g1add(theta.sigma[1], theta.nu));
    coord2[0] = theta.kappa;
    coord2[1] = G.P2();
    require(!G.isinf(theta.sigma[0]) && G.pairing(coord1, coord2));
    logging(theta.sigma, public_m);
   }
    
  }
  
  function logging( G.G1Point[2] memory sigma, string[] memory public_m) private {
    uint256[4] memory credential = [sigma[0].X, sigma[0].Y, sigma[1].X, sigma[1].Y];
    emit emitVerify(credential, public_m);
  }

  function verify_pi_v(G.G1Point[2] memory h_nu, G.G2Point[2] memory Aw_kappa, Proof memory proof,G.G1Point[] memory hs,G.G2Point memory alpha, G.G2Point[] memory beta, uint256 _timestamp) internal view returns (bool) {
    
    if(!check_Aw(Aw_kappa, proof, alpha, beta)) {
      return false;
    }

    // require(check_Aw(Aw_kappa, proof, alpha, beta));
    G.G1Point memory Bw = calculate_Bw(h_nu, proof);
    
    return proof.c == ToChallenge(alpha, Aw_kappa, Bw, hs, beta, _timestamp);
  }
    function calculate_Bw(G.G1Point[2] memory h_nu, Proof memory proof) private view returns(G.G1Point memory) {
    return (G.g1add(G.g1mul(h_nu[1], proof.c), G.g1mul(h_nu[0], proof.rt)));
  }
  function check_Aw(G.G2Point[2] memory Aw_kappa, Proof memory proof, G.G2Point memory alpha, G.G2Point[] memory beta) private view returns(bool) {
    G.G1Point[] memory AA = new G.G1Point[](proof.rm.length+5);
    G.G2Point[] memory AB = new G.G2Point[](proof.rm.length+5);

    AA[0] = G.g1neg(G.P1());
    AA[1] = G.P1();
    AA[2] = G.g1neg(G.g1mul(G.P1(), proof.c));
    AA[3] = G.g1mul(G.P1(), proof.rt);
    AA[4] = G.g1mul(G.P1(), proof.c);
    AB[0] = Aw_kappa[0];
    AB[1] = alpha;
    AB[2] = alpha;
    AB[3] = G.P2();
    AB[4] = Aw_kappa[1];

    uint256 k = 0;
    uint256 j = 0;
    for(uint256 i=0; i< proof.rm.length; i++) { 
        AA[i+5] = G.g1mul(G.P1(), proof.rm[i]);
        AB[i+5] = beta[i];
    }

    if (!G.pairing(AA, AB)) {
      return false;
    }
    return true;
    
  }

  function ToChallenge( G.G2Point memory alpha, G.G2Point[2] memory Aw_kappa, G.G1Point memory Bw, G.G1Point[] memory _hs, G.G2Point[] memory beta, uint256 _timestamp) private pure returns (uint256) {
    bytes memory result = new bytes(224 + (_hs.length + beta.length ) * 32);
    bytes32 X =  G.G1_to_binary256(G.P1());
    for (uint256 i=0; i < 32 ; i++) {
      result[i] = X[i];
    }
    X =  G.G2_to_binary256(G.P2());
    for (uint256 i=0; i< 32 ; i++) {
      result[i+32] = X[i];
    }
    X =  G.G2_to_binary256(alpha);
    for (uint256 i=0; i< 32 ; i++) {
      result[i+64] = X[i];
    }
    X =  G.G2_to_binary256(Aw_kappa[0]);
    for (uint256 i=0; i< 32 ; i++) {
      result[i+96] = X[i];
    }
    X =  G.G1_to_binary256(Bw);
    for (uint256 i=0; i< 32 ; i++) {
      result[i+128] = X[i];
    }
    X =  G.G2_to_binary256(Aw_kappa[1]);
    for (uint256 i=0; i< 32 ; i++) {
      result[i+160] = X[i];
    }
  
    uint256 location = 192;
    for(uint256 i=0; i< _hs.length; i++) {
      X = G.G1_to_binary256(_hs[i]);
      for (uint256 j=0; j< 32 ; j++) {
        result[j+location] = X[j];
      }
      location = location + 32;
    }
    for(uint256 i = 0; i < beta.length; i++) {
      X = G.G2_to_binary256(beta[i]);
      for (uint256 j=0; j< 32 ; j++) {
        result[j+location] = X[j];
      }
      location = location + 32;
    }
    X = bytes32(_timestamp);
    for(uint256 i = 0; i < 32; i++) {
      result[i+location] = X[i];
    }
    location = location + 32;

    bytes32 Chash =  sha256(result);
    return uint256(Chash);
  }

}
