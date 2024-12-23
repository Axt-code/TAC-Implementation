
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import {G} from "../libraries/G.sol";

contract SetupPublicParams {
    
    event PublicParam(address indexed client, uint256[2][] H, uint256[2][] g1_beta, uint256[4] alpha, uint256[4][] beta); 

    function sendPublicParam(G.G1Point[] memory _H, G.G2Point memory _alpha, G.G2Point[] memory _beta, G.G1Point[] memory _g1_beta ) public {
        uint256[2][] memory H = new uint256[2][](_H.length);
        uint256[2][] memory g1_beta = new uint256[2][](_g1_beta.length);
        uint256[4] memory alpha = [_alpha.X[0], _alpha.X[1],_alpha.Y[0], _alpha.Y[1]];
        uint256[4][] memory beta = new uint256[4][](_beta.length);

        for (uint256 i = 0; i < _H.length; i++) {
            H[i] = [_H[i].X, _H[i].Y];
        }

        for (uint256 i = 0; i < _g1_beta.length; i++) {
            g1_beta[i] = [_g1_beta[i].X, _g1_beta[i].Y];
        }

        for (uint256 i = 0; i < _beta.length; i++) {
             beta[i] = [_beta[i].X[0], _beta[i].X[1], _beta[i].Y[0], _beta[i].Y[1]];
        }

        emit PublicParam(msg.sender, H, g1_beta,alpha,beta);
    }
    event PublicKey(address indexed client, uint256[2][] g1_beta_i, uint256[4] alpha_i, uint256[4][] beta_i); 

    function sendPublicKey(G.G2Point memory _alpha_i, G.G2Point[] memory _beta_i, G.G1Point[] memory _g1_beta_i ) public {
        uint256[2][] memory g1_beta_i = new uint256[2][](_g1_beta_i.length);
        uint256[4] memory alpha_i = [_alpha_i.X[0], _alpha_i.X[1],_alpha_i.Y[0], _alpha_i.Y[1]];      
        uint256[4][] memory beta_i = new uint256[4][](_beta_i.length);
        for (uint256 i = 0; i < _g1_beta_i.length; i++) {
            g1_beta_i[i] = [_g1_beta_i[i].X, _g1_beta_i[i].Y];
        }
        for (uint256 i = 0; i < _beta_i.length; i++) {
             beta_i[i] = [_beta_i[i].X[0], _beta_i[i].X[1], _beta_i[i].Y[0], _beta_i[i].Y[1]];
        }
        emit PublicKey(msg.sender, g1_beta_i,alpha_i,beta_i);

    }
}


