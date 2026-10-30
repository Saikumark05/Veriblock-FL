// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x1ff9287a177f0a835b2fb0ed89592b163172dbabffe4ea8120ef31be8bb2c6a0), uint256(0x098f6268643c345036bb1fbe68ed17b9ad5e5531c3cfc934dddc166fd7aeb1cc));
        vk.beta = Pairing.G2Point([uint256(0x00215e1f1f886be96d62b7cf70bd221e1826c228944330dcae9a54295df00075), uint256(0x1ceaa493e7b1b88ba39c6807ee1e78e4497cb2052e9ffcf2cf03371a17341f55)], [uint256(0x247feeb2cf7ff5881dc6b03e9a4ce32275b2131528e5f0a0c4d04482eeebd31f), uint256(0x146b08bb1026a6718e5c9ea80a1476dae658617b9b8aa4ef9b37195a7dbd8683)]);
        vk.gamma = Pairing.G2Point([uint256(0x2b2fb92125e0b1752722538f1c82ebad6b319e525afff7d243cc805adef0b487), uint256(0x1085a6f4e27d99b0f36a2d587904ff0f3b76c0a6881633f5f243cd6082cbb9bf)], [uint256(0x11c096480f5791b4f8955f6838ab938cbfaf3ee2e51238413fb4884cfd895f22), uint256(0x1fb0e57578c9dd882eed47891792041470fb500430e1503c15acbf3e197b2d9a)]);
        vk.delta = Pairing.G2Point([uint256(0x2d6511e82d6d8f9c04193981e1e7c21b47ce9815613055076eefb9af749c0d7c), uint256(0x08d5cc192b6bbf8d2e4a544a691d15fd3bb1952162b977e97148d50f63308746)], [uint256(0x1d6a1e5d339630dd01c3a8a3e7079f770f35ebade1e23cae15dac05bffd12543), uint256(0x025dbfda3207f13be3958a11428bb5bba2ed2df96ed9b618c2f1c83500b6b82d)]);
        vk.gamma_abc = new Pairing.G1Point[](11);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x297d29931b65652983f5c4de88c9dec602f60977116361e4d7d330299b4d54e0), uint256(0x2afcafd1826db352434207c053a61bedf41fb1ee805b58c0f0630951f49570e2));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x08eef855c390e0543cee85507cfb6acda8841487f185efedbf3353e9b2c117aa), uint256(0x057543a4b4393641d12c3c405b2f486d446be6f9d20ebe1f9cd53eaaef968fbd));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x22440b1acd89cac019cdc8912d5d54d2cc428a99ab1ff57c3fa028078ca1241e), uint256(0x2e588dd528435b036e81129fd189e70aafca08ac35945b1401ca222b49e7b278));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x30033096aec786ea09bd34a558ab3fd2a97db3b086c5c22606486128bb38ec7f), uint256(0x200e349b2eda2ed0f84d1ed70a817fb20a6b5ef13993943408b02d73573b6bc7));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x260685fd9e8b5f1d6de5671f36a296e984011baf0ff4b6532e325e18261ade43), uint256(0x0d7c7b0aa96065a6559614fc134204549c780722a4023f1829a93695db4dceaf));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x012ad9783fefba0a24124cd43b7abb4a0aa6614c4c05f05531b072985fe2eb33), uint256(0x01ccad52a1b2ef8a8d9418226be9a731e94406d36c3dbf8dad750daa1adb8202));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2f371a8d3967152799a89853a98f6ef93eadbb3cf59bffbb2d9195dba73d15cf), uint256(0x02bf6478e46339a9d4faafc860a2351d206b63a06f3b10840e08db665ccb7498));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0d1043b6fadd729b56d7696f69a292e90792b1e0404af96598726bc71a83b3d4), uint256(0x2d3a165f7f77353417b06f0f764e7b8efae320a8c2256a18704a04894aeabd3c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0b8fd584cde7dd8701f5da5d8595ce3c6705187e412d7eed286328dc3a03c7a2), uint256(0x1ddf793c717ea44ab084def11adba945d0f29630c79f7e2339029a4652378164));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x17364ea418cc589ffc6ed23590a8d71068656a76bbc21429171b2ab8722bf335), uint256(0x29249504645a7d2fb6a7682dc1eccdb2ee7db41a3553f96d4528552126203faa));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x013dfc902cd00f40397bac5a4c6732a86cc8c9c35c464023113877aaeb8b1b62), uint256(0x03feebcf053a7086154123577f89253bbaf233c9b8458f06d22938ab5327fc53));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[10] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](10);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
