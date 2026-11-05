// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    DELTA = 4131629893567559867359510883348571134090853742863529169391034518566172092834;
    uint256 internal constant        R = 21888242871839275222246405745257275088548364400416034343698204186575808495617; 

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x0924;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x0ae4;

    uint256 internal constant                VK_MPTR = 0x0a60;
    uint256 internal constant         VK_DIGEST_MPTR = 0x0a60;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x0a80;
    uint256 internal constant                 K_MPTR = 0x0aa0;
    uint256 internal constant             N_INV_MPTR = 0x0ac0;
    uint256 internal constant             OMEGA_MPTR = 0x0ae0;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0b00;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0b20;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x0b40;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x0b60;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x0b80;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x0ba0;
    uint256 internal constant              G1_X_MPTR = 0x0bc0;
    uint256 internal constant              G1_Y_MPTR = 0x0be0;
    uint256 internal constant            G2_X_1_MPTR = 0x0c00;
    uint256 internal constant            G2_X_2_MPTR = 0x0c20;
    uint256 internal constant            G2_Y_1_MPTR = 0x0c40;
    uint256 internal constant            G2_Y_2_MPTR = 0x0c60;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x0c80;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x0ca0;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x0cc0;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0ce0;

    uint256 internal constant CHALLENGE_MPTR = 0x1480;

    uint256 internal constant THETA_MPTR = 0x1480;
    uint256 internal constant  BETA_MPTR = 0x14a0;
    uint256 internal constant GAMMA_MPTR = 0x14c0;
    uint256 internal constant     Y_MPTR = 0x14e0;
    uint256 internal constant     X_MPTR = 0x1500;
    uint256 internal constant  ZETA_MPTR = 0x1520;
    uint256 internal constant    NU_MPTR = 0x1540;
    uint256 internal constant    MU_MPTR = 0x1560;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x1580;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x15a0;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x15c0;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x15e0;
    uint256 internal constant             X_N_MPTR = 0x1600;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x1620;
    uint256 internal constant          L_LAST_MPTR = 0x1640;
    uint256 internal constant         L_BLIND_MPTR = 0x1660;
    uint256 internal constant             L_0_MPTR = 0x1680;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x16a0;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x16c0;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x16e0;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x1700;
    uint256 internal constant          R_EVAL_MPTR = 0x1720;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x1740;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x1760;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x1780;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x17a0;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), R)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), R)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(R, 2))
                mstore(add(gp_mptr, 0xa0), R)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), R)
                    all_inv := mulmod(all_inv, mload(mptr), R)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), R)
                let inv_second := mulmod(all_inv, mload(first_mptr), R)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field 

            // Initialize success as true
            let success := true

            {
                // Load vk_digest and num_instances of vk into memory
                mstore(0x0a60, 0x2675471b36c6b7e677741c3745c8e6eb06882a5b1528b2b67578015019adc48e) // vk_digest
                mstore(0x0a80, 0x000000000000000000000000000000000000000000000000000000000000000b) // num_instances

                // Check valid length of proof
                success := and(success, eq(0x1580, proof.length))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, instances.length))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := instances.offset
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := proof.offset
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0180) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0340) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0400) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0200) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0a40) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Load full vk into memory
                mstore(0x0a60, 0x2675471b36c6b7e677741c3745c8e6eb06882a5b1528b2b67578015019adc48e) // vk_digest
                mstore(0x0a80, 0x000000000000000000000000000000000000000000000000000000000000000b) // num_instances
                mstore(0x0aa0, 0x000000000000000000000000000000000000000000000000000000000000000e) // k
                mstore(0x0ac0, 0x30638ce1a7661b6337a964756aa75257c6bf4778d89789ab819ce60c19b04001) // n_inv
                mstore(0x0ae0, 0x2337acd19f40bf2b2aa212849e9a0c07d626d9ca335d73a09119dbe6eaab3cac) // omega
                mstore(0x0b00, 0x2f9c1d051b2a29bd1d13a09c1489aec5303c2fb2ac7d853ee7a58fdb65b90d7d) // omega_inv
                mstore(0x0b20, 0x2c34760cd8ba6180d92ad9da798faeb6fbf85f3f63d3dfca54b3b798e4f5f37e) // omega_inv_to_l
                mstore(0x0b40, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x0b60, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x0b80, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x0ba0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x0bc0, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0be0, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0c00, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x0c20, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x0c40, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x0c60, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x0c80, 0x29873a62db0d5f713a4162039493954589f6769dda3f67a6eae071db7e607f5a) // neg_s_g2_x_1
                mstore(0x0ca0, 0x2865b220303cc22dad34e99e6775f66bae945ef39f64817410ee090f7f9da6d0) // neg_s_g2_x_2
                mstore(0x0cc0, 0x2d897ed946ead1f44ceed431b81c52b95b1767361039f2746763234fd0d5f2c8) // neg_s_g2_y_1
                mstore(0x0ce0, 0x270546f0dbfe2dd7fe11808963e8c85451cac0f53c8e7d80f880b5d04e23e817) // neg_s_g2_y_2
                mstore(0x0d00, 0x28b3463004c2243490af9d29e0738a05438872e825561ef6d52472ed808bf0b7) // fixed_comms[0].x
                mstore(0x0d20, 0x2724b5405ae6c859687bbcf0ee96bc58f99c3bbbf8b8278ff6b5170cf8fdf54e) // fixed_comms[0].y
                mstore(0x0d40, 0x12323c2526e4ffebac888c91b0eb506dfb77b4ffa6bc8fd21fc3a5bc9a67335e) // fixed_comms[1].x
                mstore(0x0d60, 0x19e4322b408c28a23c6389b3cb71dca6d5b594f8201be2d469261e78b894aa9c) // fixed_comms[1].y
                mstore(0x0d80, 0x1a34c5cbfdacbd470c871006bfa39e8670af290f8eee63441df29854799bdb0e) // fixed_comms[2].x
                mstore(0x0da0, 0x197a92a5e51bdcc1a4a1a1c12bc1325ac9150b8d9ac536e3e3a033921ccae6c5) // fixed_comms[2].y
                mstore(0x0dc0, 0x27a698e2d6b681282375ef3a9ea6dcff9a4637dfbd201e3ea56d03871ca99273) // fixed_comms[3].x
                mstore(0x0de0, 0x1928595c7200ec001e2539969de242b16aa3d6fae3dc43d2658532074ead0ab2) // fixed_comms[3].y
                mstore(0x0e00, 0x12def908b3ab5520e45230a88685df6318419f2b7f6980e26213b579cbfdab8c) // fixed_comms[4].x
                mstore(0x0e20, 0x13aa905b8949c84cf09e69d22b9706f3402a1b785963eeda2938c0e3eac2cf82) // fixed_comms[4].y
                mstore(0x0e40, 0x13aa3337a419a187523fad56c4df85da5877c6102bf17cb39554c9cdfb16818a) // fixed_comms[5].x
                mstore(0x0e60, 0x084cbc3e7c1358c6cfeb13e3dd5ed86795d16ff4dfff5037b6088372446ff71a) // fixed_comms[5].y
                mstore(0x0e80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[6].x
                mstore(0x0ea0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[6].y
                mstore(0x0ec0, 0x0e1a84f52d98ca69406d1d45c73d1408d5ba1b4930b744db4a4e03ee9377e241) // fixed_comms[7].x
                mstore(0x0ee0, 0x0ed3bb7cf499d5727688b29f72792ba735bdca6add9218f2821acac6f11b1a7e) // fixed_comms[7].y
                mstore(0x0f00, 0x1428b0c0a8468246bdc4bbb709c842d1c02a6169aefa089b9132ed046386be63) // fixed_comms[8].x
                mstore(0x0f20, 0x1d434ffaf41f67960027adc2a7fb8b77d12beec018b3f54751776b170dd5c9de) // fixed_comms[8].y
                mstore(0x0f40, 0x2eda7c736c3900d80af53b00c2e19e84c49d63fb6df55ea567bf634a8b3af61b) // fixed_comms[9].x
                mstore(0x0f60, 0x0dd1cc046de33abca0b196965a175377c716327f38e26fbd8c0d4895efe27007) // fixed_comms[9].y
                mstore(0x0f80, 0x04f65f23fad6bc9f9315e2b5907599367dd1499f454152e1b82e5bc4613c541a) // fixed_comms[10].x
                mstore(0x0fa0, 0x30381285673eef4aed568447201ac44a0e197499e00760f6d76b136c0b813e53) // fixed_comms[10].y
                mstore(0x0fc0, 0x0bfe62b28a8b4dc927142209f19109bcab193a8e2655bfc25cc1bbc6349dee56) // fixed_comms[11].x
                mstore(0x0fe0, 0x24873509586e1483b573ee45b292cf41f6e7250070c40e6bf47aa4d267455bae) // fixed_comms[11].y
                mstore(0x1000, 0x172eb9c604dbd1f8030e0c322571533d3767f60dbd92efded83b78bed4d179a1) // fixed_comms[12].x
                mstore(0x1020, 0x08856d60462c0e1aca69c5c8921f6dab6d998205e7923bafbb9d559c7a63cf94) // fixed_comms[12].y
                mstore(0x1040, 0x0e0ec511ceb5b86689c448b920bb6f0dc1a2147c90f2ac57e38e910df481b685) // fixed_comms[13].x
                mstore(0x1060, 0x24885b1b3c044e8afe9c5fad39ee32b353e2d322b0cabfb0153d32bce7c0a267) // fixed_comms[13].y
                mstore(0x1080, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[14].x
                mstore(0x10a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[14].y
                mstore(0x10c0, 0x0384501c6b52c631592cd29c8c0f8bc2dfd40a30f7a415501421e84c77250425) // fixed_comms[15].x
                mstore(0x10e0, 0x276f57373f4819c4a2c5517624af156805c652ecd1f034f817411360911a19b0) // fixed_comms[15].y
                mstore(0x1100, 0x0535974ff14bb6c751e432e1390a463b7f84a00d8bf4bb7556598110567fdf47) // fixed_comms[16].x
                mstore(0x1120, 0x2303a8a605337e96cd54cc3f1911c99558d7f620fef33e4adbe7392dcd79f73d) // fixed_comms[16].y
                mstore(0x1140, 0x0535974ff14bb6c751e432e1390a463b7f84a00d8bf4bb7556598110567fdf47) // fixed_comms[17].x
                mstore(0x1160, 0x2303a8a605337e96cd54cc3f1911c99558d7f620fef33e4adbe7392dcd79f73d) // fixed_comms[17].y
                mstore(0x1180, 0x2194dc5019acaa91bf38948189776e0490ef23077ee3174bd7ca9933ef513f66) // fixed_comms[18].x
                mstore(0x11a0, 0x21e3d369eca2426f56d3d394017ded20639212608a9f908e075de8196e07dd6d) // fixed_comms[18].y
                mstore(0x11c0, 0x19e14ca250549e2e72a1287473857fdfea2eb0885e93da8caf2a24aea9939dd5) // fixed_comms[19].x
                mstore(0x11e0, 0x27b097bea40bf7e07bcaf36f97ab72c0f3f9f41279472c1eba007fdd5af9c333) // fixed_comms[19].y
                mstore(0x1200, 0x2a8705d24499ecd39579da5dd23778ef5dd3410f64be03f3f25a806c66d80dd6) // fixed_comms[20].x
                mstore(0x1220, 0x08caa622040e4354cc3534e834506032d9497265382a915dce0349ae3a7395ad) // fixed_comms[20].y
                mstore(0x1240, 0x157659748baf44ad84aa5db0f019adf7a485d01c7d8351a74b4733cf0f513dd5) // fixed_comms[21].x
                mstore(0x1260, 0x12a5cf6310b008191994c43c21011f9dc77e675d335e90e6941994f7f14d4883) // fixed_comms[21].y
                mstore(0x1280, 0x0df264b99aec135262a444702ed0b6cac8d1b77858dcb8fe46cca261107af9bf) // permutation_comms[0].x
                mstore(0x12a0, 0x1d756741e1b64f4ce3381980feaf7f6bbbd9d9a471665c37b29aede3284a767f) // permutation_comms[0].y
                mstore(0x12c0, 0x0c3e367ae16eedb9c2a607e4f85b2050e96c64f5d5ce13080658d3f6ef8712d1) // permutation_comms[1].x
                mstore(0x12e0, 0x09c534638eeea19f3dcb8d565ee078baa7b7c21d834bba4d768b1f235bcf53f1) // permutation_comms[1].y
                mstore(0x1300, 0x22f5594ee296a427407db41c667946e98500d19437ba8f38b4d2d001f1acb598) // permutation_comms[2].x
                mstore(0x1320, 0x281cd8239a350af464004767042d52b43085761275da42527ea87d2bb546deb2) // permutation_comms[2].y
                mstore(0x1340, 0x0a7ea27cb2490ce2b6de8fa0d36471556296cdfbee9c4ab482b5899db5e85f54) // permutation_comms[3].x
                mstore(0x1360, 0x010ad671fd8391640b3c7f8835a696d7c0b64bfe3498233232817004b581c63a) // permutation_comms[3].y
                mstore(0x1380, 0x2492674a46542fcf6a27d80f4b252269171086e0e77f6e5493d0eb450a362644) // permutation_comms[4].x
                mstore(0x13a0, 0x221db59f158cd098e03d6a6c7d6d60105128b209132eea97dbd222dbf5e36d5a) // permutation_comms[4].y
                mstore(0x13c0, 0x2cd1316599c87b2e38a57870962dde03eb74617113e83fad6c23a54c967e17f4) // permutation_comms[5].x
                mstore(0x13e0, 0x0c79278d51e254b36f663c427c2e6dfffc005541ace2381809c0889c257bfb29) // permutation_comms[5].y
                mstore(0x1400, 0x024eb6507e66acb88d83ae4c920d0e0df8620bd34f4fdbabf68f3c14035b3807) // permutation_comms[6].x
                mstore(0x1420, 0x2ebf0c9a7b4f70611d47b6f722a2f0ada24775074cd443b2d8f34cb37d313e86) // permutation_comms[6].y
                mstore(0x1440, 0x05692c4c022cf5ecbde2ebbff3b7e8bcbafd4a7ac653d510d5335111c375bdf6) // permutation_comms[7].x
                mstore(0x1460, 0x19b04196b32102652c6c86ce6766ce902661d094e0a06cc275acd48ef3034076) // permutation_comms[7].y

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(instances.offset, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20))

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := instances.offset
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let y := mload(Y_MPTR)
                {
                    let f_20 := calldataload(0x0e84)
                    let var0 := 0x2
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0ba4)
                    let a_0 := calldataload(0x0b24)
                    let a_2 := calldataload(0x0b64)
                    let var16 := addmod(a_0, a_2, R)
                    let var17 := sub(R, var16)
                    let var18 := addmod(a_4, var17, R)
                    let var19 := mulmod(var15, var18, R)
                    quotient_eval_numer := var19
                }
                {
                    let f_21 := calldataload(0x0ea4)
                    let var0 := 0x2
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_5 := calldataload(0x0bc4)
                    let a_1 := calldataload(0x0b44)
                    let a_3 := calldataload(0x0b84)
                    let var16 := addmod(a_1, a_3, R)
                    let var17 := sub(R, var16)
                    let var18 := addmod(a_5, var17, R)
                    let var19 := mulmod(var15, var18, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var19, r)
                }
                {
                    let f_20 := calldataload(0x0e84)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0ba4)
                    let a_0 := calldataload(0x0b24)
                    let a_2 := calldataload(0x0b64)
                    let var16 := mulmod(a_0, a_2, R)
                    let var17 := sub(R, var16)
                    let var18 := addmod(a_4, var17, R)
                    let var19 := mulmod(var15, var18, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var19, r)
                }
                {
                    let f_21 := calldataload(0x0ea4)
                    let var0 := 0x1
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_5 := calldataload(0x0bc4)
                    let a_1 := calldataload(0x0b44)
                    let a_3 := calldataload(0x0b84)
                    let var16 := mulmod(a_1, a_3, R)
                    let var17 := sub(R, var16)
                    let var18 := addmod(a_5, var17, R)
                    let var19 := mulmod(var15, var18, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var19, r)
                }
                {
                    let f_20 := calldataload(0x0e84)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0ba4)
                    let a_0 := calldataload(0x0b24)
                    let a_2 := calldataload(0x0b64)
                    let var16 := sub(R, a_2)
                    let var17 := addmod(a_0, var16, R)
                    let var18 := sub(R, var17)
                    let var19 := addmod(a_4, var18, R)
                    let var20 := mulmod(var15, var19, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var20, r)
                }
                {
                    let f_21 := calldataload(0x0ea4)
                    let var0 := 0x1
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_5 := calldataload(0x0bc4)
                    let a_1 := calldataload(0x0b44)
                    let a_3 := calldataload(0x0b84)
                    let var16 := sub(R, a_3)
                    let var17 := addmod(a_1, var16, R)
                    let var18 := sub(R, var17)
                    let var19 := addmod(a_5, var18, R)
                    let var20 := mulmod(var15, var19, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var20, r)
                }
                {
                    let f_20 := calldataload(0x0e84)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x4
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0ba4)
                    let a_4_prev_1 := calldataload(0x0be4)
                    let var16 := 0x0
                    let a_0 := calldataload(0x0b24)
                    let a_2 := calldataload(0x0b64)
                    let var17 := mulmod(a_0, a_2, R)
                    let var18 := addmod(var16, var17, R)
                    let a_1 := calldataload(0x0b44)
                    let a_3 := calldataload(0x0b84)
                    let var19 := mulmod(a_1, a_3, R)
                    let var20 := addmod(var18, var19, R)
                    let var21 := addmod(a_4_prev_1, var20, R)
                    let var22 := sub(R, var21)
                    let var23 := addmod(a_4, var22, R)
                    let var24 := mulmod(var15, var23, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var24, r)
                }
                {
                    let f_20 := calldataload(0x0e84)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0ba4)
                    let var16 := 0x0
                    let a_0 := calldataload(0x0b24)
                    let a_2 := calldataload(0x0b64)
                    let var17 := mulmod(a_0, a_2, R)
                    let var18 := addmod(var16, var17, R)
                    let a_1 := calldataload(0x0b44)
                    let a_3 := calldataload(0x0b84)
                    let var19 := mulmod(a_1, a_3, R)
                    let var20 := addmod(var18, var19, R)
                    let var21 := sub(R, var20)
                    let var22 := addmod(a_4, var21, R)
                    let var23 := mulmod(var15, var22, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var23, r)
                }
                {
                    let f_21 := calldataload(0x0ea4)
                    let var0 := 0x1
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0ba4)
                    let a_2 := calldataload(0x0b64)
                    let var16 := mulmod(var0, a_2, R)
                    let a_3 := calldataload(0x0b84)
                    let var17 := mulmod(var16, a_3, R)
                    let var18 := sub(R, var17)
                    let var19 := addmod(a_4, var18, R)
                    let var20 := mulmod(var15, var19, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var20, r)
                }
                {
                    let f_20 := calldataload(0x0e84)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x4
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x5
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0ba4)
                    let a_4_prev_1 := calldataload(0x0be4)
                    let a_2 := calldataload(0x0b64)
                    let var16 := mulmod(var0, a_2, R)
                    let a_3 := calldataload(0x0b84)
                    let var17 := mulmod(var16, a_3, R)
                    let var18 := mulmod(a_4_prev_1, var17, R)
                    let var19 := sub(R, var18)
                    let var20 := addmod(a_4, var19, R)
                    let var21 := mulmod(var15, var20, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var21, r)
                }
                {
                    let f_21 := calldataload(0x0ea4)
                    let var0 := 0x1
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x4
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x5
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0ba4)
                    let var16 := 0x0
                    let a_2 := calldataload(0x0b64)
                    let var17 := addmod(var16, a_2, R)
                    let a_3 := calldataload(0x0b84)
                    let var18 := addmod(var17, a_3, R)
                    let var19 := sub(R, var18)
                    let var20 := addmod(a_4, var19, R)
                    let var21 := mulmod(var15, var20, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var21, r)
                }
                {
                    let f_21 := calldataload(0x0ea4)
                    let var0 := 0x1
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x4
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0ba4)
                    let a_4_prev_1 := calldataload(0x0be4)
                    let var16 := 0x0
                    let a_2 := calldataload(0x0b64)
                    let var17 := addmod(var16, a_2, R)
                    let a_3 := calldataload(0x0b84)
                    let var18 := addmod(var17, a_3, R)
                    let var19 := addmod(a_4_prev_1, var18, R)
                    let var20 := sub(R, var19)
                    let var21 := addmod(a_4, var20, R)
                    let var22 := mulmod(var15, var21, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var22, r)
                }
                {
                    let f_14 := calldataload(0x0dc4)
                    let var0 := 0x1
                    let a_2 := calldataload(0x0b64)
                    let var1 := 0x0
                    let var2 := sub(R, var1)
                    let var3 := addmod(a_2, var2, R)
                    let var4 := mulmod(var0, var3, R)
                    let var5 := sub(R, var0)
                    let var6 := addmod(a_2, var5, R)
                    let var7 := mulmod(var4, var6, R)
                    let var8 := 0x2
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_2, var9, R)
                    let var11 := mulmod(var7, var10, R)
                    let var12 := 0x3
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_2, var13, R)
                    let var15 := mulmod(var11, var14, R)
                    let var16 := 0x4
                    let var17 := sub(R, var16)
                    let var18 := addmod(a_2, var17, R)
                    let var19 := mulmod(var15, var18, R)
                    let var20 := mulmod(f_14, var19, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var20, r)
                }
                {
                    let f_15 := calldataload(0x0de4)
                    let var0 := 0x1
                    let a_3 := calldataload(0x0b84)
                    let var1 := 0x0
                    let var2 := sub(R, var1)
                    let var3 := addmod(a_3, var2, R)
                    let var4 := mulmod(var0, var3, R)
                    let var5 := sub(R, var0)
                    let var6 := addmod(a_3, var5, R)
                    let var7 := mulmod(var4, var6, R)
                    let var8 := 0x2
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_3, var9, R)
                    let var11 := mulmod(var7, var10, R)
                    let var12 := 0x3
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_3, var13, R)
                    let var15 := mulmod(var11, var14, R)
                    let var16 := 0x4
                    let var17 := sub(R, var16)
                    let var18 := addmod(a_3, var17, R)
                    let var19 := mulmod(var15, var18, R)
                    let var20 := mulmod(f_15, var19, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var20, r)
                }
                {
                    let f_16 := calldataload(0x0e04)
                    let var0 := 0x1
                    let a_2 := calldataload(0x0b64)
                    let var1 := 0x0
                    let var2 := sub(R, var1)
                    let var3 := addmod(a_2, var2, R)
                    let var4 := mulmod(var0, var3, R)
                    let var5 := sub(R, var0)
                    let var6 := addmod(a_2, var5, R)
                    let var7 := mulmod(var4, var6, R)
                    let var8 := mulmod(f_16, var7, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var8, r)
                }
                {
                    let f_17 := calldataload(0x0e24)
                    let var0 := 0x1
                    let a_3 := calldataload(0x0b84)
                    let var1 := 0x0
                    let var2 := sub(R, var1)
                    let var3 := addmod(a_3, var2, R)
                    let var4 := mulmod(var0, var3, R)
                    let var5 := sub(R, var0)
                    let var6 := addmod(a_3, var5, R)
                    let var7 := mulmod(var4, var6, R)
                    let var8 := mulmod(f_17, var7, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var8, r)
                }
                {
                    let f_18 := calldataload(0x0e44)
                    let var0 := 0x0
                    let var1 := mulmod(f_18, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_19 := calldataload(0x0e64)
                    let var0 := 0x0
                    let var1 := mulmod(f_19, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(R, mulmod(l_0, calldataload(0x0fe4), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x1044)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, R), sub(R, perm_z_last), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1044), sub(R, calldataload(0x1024)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1004)
                    let rhs := calldataload(0x0fe4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b24), mulmod(beta, calldataload(0x0ee4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b44), mulmod(beta, calldataload(0x0f04), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b64), mulmod(beta, calldataload(0x0f24), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b84), mulmod(beta, calldataload(0x0f44), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ba4), mulmod(beta, calldataload(0x0f64), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0bc4), mulmod(beta, calldataload(0x0f84), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0c04), mulmod(beta, calldataload(0x0fa4), R), R), gamma, R), R)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b24), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b44), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b64), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b84), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ba4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0bc4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0c04), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1064)
                    let rhs := calldataload(0x1044)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x0fc4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), R), gamma, R), R)
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1084), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1084), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_11 := calldataload(0x0d64)
                        table := f_11
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_16 := calldataload(0x0e04)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0b64)
                        let var1 := sub(R, a_2)
                        let var2 := addmod(var0, var1, R)
                        let var3 := mulmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(f_16, var4, R)
                        let a_0 := calldataload(0x0b24)
                        let var6 := mulmod(var5, a_0, R)
                        let var7 := sub(R, var5)
                        let var8 := addmod(var0, var7, R)
                        let var9 := 0x0
                        let var10 := mulmod(var8, var9, R)
                        let var11 := addmod(var6, var10, R)
                        input_0 := var11
                        input_0 := addmod(input_0, beta, R)
                    }
                    let input_1
                    {
                        let f_17 := calldataload(0x0e24)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0b84)
                        let var1 := sub(R, a_3)
                        let var2 := addmod(var0, var1, R)
                        let var3 := mulmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(f_17, var4, R)
                        let a_1 := calldataload(0x0b44)
                        let var6 := mulmod(var5, a_1, R)
                        let var7 := sub(R, var5)
                        let var8 := addmod(var0, var7, R)
                        let var9 := 0x0
                        let var10 := mulmod(var8, var9, R)
                        let var11 := addmod(var6, var10, R)
                        input_1 := var11
                        input_1 := addmod(input_1, beta, R)
                    }
                    let lhs
                    let rhs
                    {
                        let tmp := input_1
                        rhs := addmod(rhs, tmp, R)
                    }
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, tmp, R)
                        rhs := mulmod(rhs, table, R)
                    }
                    {
                        let tmp := input_0
                        tmp := mulmod(tmp, input_1, R)
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x10c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x10a4), sub(R, calldataload(0x1084)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x10e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x10e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_12 := calldataload(0x0d84)
                        table := f_12
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_16 := calldataload(0x0e04)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0b64)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := mulmod(var1, var0, R)
                        let var3 := mulmod(f_16, var2, R)
                        let a_0 := calldataload(0x0b24)
                        let var4 := mulmod(var3, a_0, R)
                        let var5 := sub(R, var3)
                        let var6 := addmod(var0, var5, R)
                        let var7 := 0x3ff8
                        let var8 := mulmod(var6, var7, R)
                        let var9 := addmod(var4, var8, R)
                        input_0 := var9
                        input_0 := addmod(input_0, beta, R)
                    }
                    let input_1
                    {
                        let f_17 := calldataload(0x0e24)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0b84)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := mulmod(var1, var0, R)
                        let var3 := mulmod(f_17, var2, R)
                        let a_1 := calldataload(0x0b44)
                        let var4 := mulmod(var3, a_1, R)
                        let var5 := sub(R, var3)
                        let var6 := addmod(var0, var5, R)
                        let var7 := 0x3ff8
                        let var8 := mulmod(var6, var7, R)
                        let var9 := addmod(var4, var8, R)
                        input_1 := var9
                        input_1 := addmod(input_1, beta, R)
                    }
                    let lhs
                    let rhs
                    {
                        let tmp := input_1
                        rhs := addmod(rhs, tmp, R)
                    }
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, tmp, R)
                        rhs := mulmod(rhs, table, R)
                    }
                    {
                        let tmp := input_0
                        tmp := mulmod(tmp, input_1, R)
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1124), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1104), sub(R, calldataload(0x10e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1144), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1144), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_13 := calldataload(0x0da4)
                        table := f_13
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_18 := calldataload(0x0e44)
                        let var0 := 0x1
                        let var1 := mulmod(f_18, var0, R)
                        let a_0 := calldataload(0x0b24)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let input_1
                    {
                        let f_19 := calldataload(0x0e64)
                        let var0 := 0x1
                        let var1 := mulmod(f_19, var0, R)
                        let a_1 := calldataload(0x0b44)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_1 := var7
                        input_1 := addmod(input_1, beta, R)
                    }
                    let lhs
                    let rhs
                    {
                        let tmp := input_1
                        rhs := addmod(rhs, tmp, R)
                    }
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, tmp, R)
                        rhs := mulmod(rhs, table, R)
                    }
                    {
                        let tmp := input_0
                        tmp := mulmod(tmp, input_1, R)
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1184), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1164), sub(R, calldataload(0x1144)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x11a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x11a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0c24)
                        let f_6 := calldataload(0x0c44)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_6, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_14 := calldataload(0x0dc4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0b64)
                        let var1 := sub(R, a_2)
                        let var2 := addmod(var0, var1, R)
                        let var3 := mulmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := 0x2
                        let var6 := addmod(var5, var1, R)
                        let var7 := mulmod(var0, var6, R)
                        let var8 := 0x3
                        let var9 := addmod(var8, var1, R)
                        let var10 := mulmod(var0, var9, R)
                        let var11 := 0x4
                        let var12 := addmod(var11, var1, R)
                        let var13 := mulmod(var0, var12, R)
                        let var14 := mulmod(var10, var13, R)
                        let var15 := mulmod(var7, var14, R)
                        let var16 := mulmod(var4, var15, R)
                        let var17 := mulmod(f_14, var16, R)
                        let a_0 := calldataload(0x0b24)
                        let var18 := mulmod(var17, a_0, R)
                        let var19 := 0x18
                        let var20 := sub(R, var17)
                        let var21 := addmod(var19, var20, R)
                        let var22 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var23 := mulmod(var21, var22, R)
                        let var24 := addmod(var18, var23, R)
                        let a_4 := calldataload(0x0ba4)
                        let var25 := mulmod(var17, a_4, R)
                        let var26 := 0x0
                        let var27 := mulmod(var21, var26, R)
                        let var28 := addmod(var25, var27, R)
                        input_0 := var24
                        input_0 := addmod(mulmod(input_0, theta, R), var28, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x11e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x11c4), sub(R, calldataload(0x11a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1204), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1204), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0c24)
                        let f_6 := calldataload(0x0c44)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_6, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_15 := calldataload(0x0de4)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0b84)
                        let var1 := sub(R, a_3)
                        let var2 := addmod(var0, var1, R)
                        let var3 := mulmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := 0x2
                        let var6 := addmod(var5, var1, R)
                        let var7 := mulmod(var0, var6, R)
                        let var8 := 0x3
                        let var9 := addmod(var8, var1, R)
                        let var10 := mulmod(var0, var9, R)
                        let var11 := 0x4
                        let var12 := addmod(var11, var1, R)
                        let var13 := mulmod(var0, var12, R)
                        let var14 := mulmod(var10, var13, R)
                        let var15 := mulmod(var7, var14, R)
                        let var16 := mulmod(var4, var15, R)
                        let var17 := mulmod(f_15, var16, R)
                        let a_1 := calldataload(0x0b44)
                        let var18 := mulmod(var17, a_1, R)
                        let var19 := 0x18
                        let var20 := sub(R, var17)
                        let var21 := addmod(var19, var20, R)
                        let var22 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var23 := mulmod(var21, var22, R)
                        let var24 := addmod(var18, var23, R)
                        let a_5 := calldataload(0x0bc4)
                        let var25 := mulmod(var17, a_5, R)
                        let var26 := 0x0
                        let var27 := mulmod(var21, var26, R)
                        let var28 := addmod(var25, var27, R)
                        input_0 := var24
                        input_0 := addmod(mulmod(input_0, theta, R), var28, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1244), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1224), sub(R, calldataload(0x1204)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1264), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1264), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0c64)
                        let f_7 := calldataload(0x0c84)
                        table := f_2
                        table := addmod(mulmod(table, theta, R), f_7, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_14 := calldataload(0x0dc4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0b64)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := mulmod(var1, var0, R)
                        let var3 := 0x2
                        let var4 := sub(R, a_2)
                        let var5 := addmod(var3, var4, R)
                        let var6 := mulmod(var0, var5, R)
                        let var7 := 0x3
                        let var8 := addmod(var7, var4, R)
                        let var9 := mulmod(var0, var8, R)
                        let var10 := 0x4
                        let var11 := addmod(var10, var4, R)
                        let var12 := mulmod(var0, var11, R)
                        let var13 := mulmod(var9, var12, R)
                        let var14 := mulmod(var6, var13, R)
                        let var15 := mulmod(var2, var14, R)
                        let var16 := mulmod(f_14, var15, R)
                        let a_0 := calldataload(0x0b24)
                        let var17 := mulmod(var16, a_0, R)
                        let var18 := 0x6
                        let var19 := sub(R, var16)
                        let var20 := addmod(var18, var19, R)
                        let var21 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffbff9
                        let var22 := mulmod(var20, var21, R)
                        let var23 := addmod(var17, var22, R)
                        let a_4 := calldataload(0x0ba4)
                        let var24 := mulmod(var16, a_4, R)
                        let var25 := 0x0
                        let var26 := mulmod(var20, var25, R)
                        let var27 := addmod(var24, var26, R)
                        input_0 := var23
                        input_0 := addmod(mulmod(input_0, theta, R), var27, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x12a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1284), sub(R, calldataload(0x1264)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x12c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x12c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0c64)
                        let f_7 := calldataload(0x0c84)
                        table := f_2
                        table := addmod(mulmod(table, theta, R), f_7, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_15 := calldataload(0x0de4)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0b84)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := mulmod(var1, var0, R)
                        let var3 := 0x2
                        let var4 := sub(R, a_3)
                        let var5 := addmod(var3, var4, R)
                        let var6 := mulmod(var0, var5, R)
                        let var7 := 0x3
                        let var8 := addmod(var7, var4, R)
                        let var9 := mulmod(var0, var8, R)
                        let var10 := 0x4
                        let var11 := addmod(var10, var4, R)
                        let var12 := mulmod(var0, var11, R)
                        let var13 := mulmod(var9, var12, R)
                        let var14 := mulmod(var6, var13, R)
                        let var15 := mulmod(var2, var14, R)
                        let var16 := mulmod(f_15, var15, R)
                        let a_1 := calldataload(0x0b44)
                        let var17 := mulmod(var16, a_1, R)
                        let var18 := 0x6
                        let var19 := sub(R, var16)
                        let var20 := addmod(var18, var19, R)
                        let var21 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffbff9
                        let var22 := mulmod(var20, var21, R)
                        let var23 := addmod(var17, var22, R)
                        let a_5 := calldataload(0x0bc4)
                        let var24 := mulmod(var16, a_5, R)
                        let var25 := 0x0
                        let var26 := mulmod(var20, var25, R)
                        let var27 := addmod(var24, var26, R)
                        input_0 := var23
                        input_0 := addmod(mulmod(input_0, theta, R), var27, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1304), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x12e4), sub(R, calldataload(0x12c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1324), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1324), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0ca4)
                        let f_8 := calldataload(0x0cc4)
                        table := f_3
                        table := addmod(mulmod(table, theta, R), f_8, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_14 := calldataload(0x0dc4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0b64)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := sub(R, a_2)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x3
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x4
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var8, var11, R)
                        let var13 := mulmod(var0, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_14, var14, R)
                        let a_0 := calldataload(0x0b24)
                        let var16 := mulmod(var15, a_0, R)
                        let var17 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffd
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffff1
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        let a_4 := calldataload(0x0ba4)
                        let var23 := mulmod(var15, a_4, R)
                        let var24 := 0x3c
                        let var25 := mulmod(var19, var24, R)
                        let var26 := addmod(var23, var25, R)
                        input_0 := var22
                        input_0 := addmod(mulmod(input_0, theta, R), var26, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1364), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1344), sub(R, calldataload(0x1324)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1384), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1384), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0ca4)
                        let f_8 := calldataload(0x0cc4)
                        table := f_3
                        table := addmod(mulmod(table, theta, R), f_8, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_15 := calldataload(0x0de4)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0b84)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := sub(R, a_3)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x3
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x4
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var8, var11, R)
                        let var13 := mulmod(var0, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_15, var14, R)
                        let a_1 := calldataload(0x0b44)
                        let var16 := mulmod(var15, a_1, R)
                        let var17 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffd
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffff1
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        let a_5 := calldataload(0x0bc4)
                        let var23 := mulmod(var15, a_5, R)
                        let var24 := 0x3c
                        let var25 := mulmod(var19, var24, R)
                        let var26 := addmod(var23, var25, R)
                        input_0 := var22
                        input_0 := addmod(mulmod(input_0, theta, R), var26, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x13c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x13a4), sub(R, calldataload(0x1384)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x13e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x13e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x0ce4)
                        let f_9 := calldataload(0x0d04)
                        table := f_4
                        table := addmod(mulmod(table, theta, R), f_9, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_14 := calldataload(0x0dc4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0b64)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := sub(R, a_2)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x2
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x4
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var0, var11, R)
                        let var13 := mulmod(var8, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_14, var14, R)
                        let a_0 := calldataload(0x0b24)
                        let var16 := mulmod(var15, a_0, R)
                        let var17 := 0x6
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x3fe8
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        let a_4 := calldataload(0x0ba4)
                        let var23 := mulmod(var15, a_4, R)
                        let var24 := 0x80
                        let var25 := mulmod(var19, var24, R)
                        let var26 := addmod(var23, var25, R)
                        input_0 := var22
                        input_0 := addmod(mulmod(input_0, theta, R), var26, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1424), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1404), sub(R, calldataload(0x13e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1444), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1444), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x0ce4)
                        let f_9 := calldataload(0x0d04)
                        table := f_4
                        table := addmod(mulmod(table, theta, R), f_9, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_15 := calldataload(0x0de4)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0b84)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := sub(R, a_3)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x2
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x4
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var0, var11, R)
                        let var13 := mulmod(var8, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_15, var14, R)
                        let a_1 := calldataload(0x0b44)
                        let var16 := mulmod(var15, a_1, R)
                        let var17 := 0x6
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x3fe8
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        let a_5 := calldataload(0x0bc4)
                        let var23 := mulmod(var15, a_5, R)
                        let var24 := 0x80
                        let var25 := mulmod(var19, var24, R)
                        let var26 := addmod(var23, var25, R)
                        input_0 := var22
                        input_0 := addmod(mulmod(input_0, theta, R), var26, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1484), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1464), sub(R, calldataload(0x1444)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x14a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x14a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x0d24)
                        let f_10 := calldataload(0x0d44)
                        table := f_5
                        table := addmod(mulmod(table, theta, R), f_10, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_14 := calldataload(0x0dc4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0b64)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := sub(R, a_2)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x2
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x3
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var11, var0, R)
                        let var13 := mulmod(var8, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_14, var14, R)
                        let a_0 := calldataload(0x0b24)
                        let var16 := mulmod(var15, a_0, R)
                        let var17 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffe9
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x7fe0
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        let a_4 := calldataload(0x0ba4)
                        let var23 := mulmod(var15, a_4, R)
                        let var24 := 0x80
                        let var25 := mulmod(var19, var24, R)
                        let var26 := addmod(var23, var25, R)
                        input_0 := var22
                        input_0 := addmod(mulmod(input_0, theta, R), var26, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x14e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x14c4), sub(R, calldataload(0x14a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1504), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1504), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x0d24)
                        let f_10 := calldataload(0x0d44)
                        table := f_5
                        table := addmod(mulmod(table, theta, R), f_10, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_15 := calldataload(0x0de4)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0b84)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := sub(R, a_3)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x2
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x3
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var11, var0, R)
                        let var13 := mulmod(var8, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_15, var14, R)
                        let a_1 := calldataload(0x0b44)
                        let var16 := mulmod(var15, a_1, R)
                        let var17 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffe9
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x7fe0
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        let a_5 := calldataload(0x0bc4)
                        let var23 := mulmod(var15, a_5, R)
                        let var24 := 0x80
                        let var25 := mulmod(var19, var24, R)
                        let var26 := addmod(var23, var25, R)
                        input_0 := var22
                        input_0 := addmod(mulmod(input_0, theta, R), var26, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1544), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1524), sub(R, calldataload(0x1504)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, R)
                    mstore(0x0360, x_pow_of_omega)
                    mstore(0x0340, x)
                    x_pow_of_omega := mulmod(x, omega_inv, R)
                    mstore(0x0320, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    mstore(0x0300, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x0380
                            let mptr_end := 0x0400
                            let point_mptr := 0x0300
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(R, mload(point_mptr)), R))
                    }
                    let s
                    s := mload(0x03c0)
                    mstore(0x0400, s)
                    let diff
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0420, diff)
                    mstore(0x00, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0440, diff)
                    diff := mload(0x03a0)
                    mstore(0x0460, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    mstore(0x0480, diff)
                }
                {
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x20, coeff)
                }
                {
                    let point_1 := mload(0x0320)
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := addmod(point_1, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03a0), R)
                    mstore(0x40, coeff)
                    coeff := addmod(point_2, sub(R, point_1), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x60, coeff)
                }
                {
                    let point_0 := mload(0x0300)
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_0, sub(R, point_2), R)
                    coeff := mulmod(coeff, addmod(point_0, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x0380), R)
                    mstore(0x80, coeff)
                    coeff := addmod(point_2, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_2, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_3, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_3, sub(R, point_2), R), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0xc0, coeff)
                }
                {
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_2, sub(R, point_3), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_3, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0x0100, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0120)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0420, diff_0_inv)
                    for
                        {
                            let mptr := 0x0440
                            let mptr_end := 0x04a0
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, R))
                    }
                }
                {
                    let coeff := mload(0x20)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0ec4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), R), R)
                    for
                        {
                            let mptr := 0x0fc4
                            let mptr_end := 0x0ec4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    for
                        {
                            let mptr := 0x0ea4
                            let mptr_end := 0x0be4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1544), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x14e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1484), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1424), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x13c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1364), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1304), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x12a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1244), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x11e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1184), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1124), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x10c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0bc4), R), R)
                    for
                        {
                            let mptr := 0x0b84
                            let mptr_end := 0x0b04
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    mstore(0x04a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0be4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0ba4), R), R)
                    r_eval := mulmod(r_eval, mload(0x0440), R)
                    mstore(0x04c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x1024), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0fe4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x1004), R), R)
                    r_eval := mulmod(r_eval, mload(0x0460), R)
                    mstore(0x04e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1504), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1524), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x14a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x14c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1444), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1464), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x13e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1404), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1384), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x13a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1324), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1344), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x12c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x12e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1264), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1284), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1204), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1224), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x11a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x11c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1144), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1164), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x10e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1104), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1084), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x10a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1044), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1064), R), R)
                    r_eval := mulmod(r_eval, mload(0x0480), R)
                    mstore(0x0500, r_eval)
                }
                {
                    let sum := mload(0x20)
                    mstore(0x0520, sum)
                }
                {
                    let sum := mload(0x40)
                    sum := addmod(sum, mload(0x60), R)
                    mstore(0x0540, sum)
                }
                {
                    let sum := mload(0x80)
                    sum := addmod(sum, mload(0xa0), R)
                    sum := addmod(sum, mload(0xc0), R)
                    mstore(0x0560, sum)
                }
                {
                    let sum := mload(0xe0)
                    sum := addmod(sum, mload(0x0100), R)
                    mstore(0x0580, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0x80
                            let sum_mptr := 0x0520
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x80)
                    let r_eval := mulmod(mload(0x60), mload(0x0500), R)
                    for
                        {
                            let sum_inv_mptr := 0x40
                            let sum_inv_mptr_end := 0x80
                            let r_eval_mptr := 0x04e0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), R)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), R), R)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x08e4))
                    mstore(0x20, calldataload(0x0904))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x1440
                            let mptr_end := 0x0f40
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0e40), mload(0x0e60))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0f40), mload(0x0f60))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0e00), mload(0x0e20))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0f00), mload(0x0f20))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0dc0), mload(0x0de0))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0ec0), mload(0x0ee0))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0d80), mload(0x0da0))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0e80), mload(0x0ea0))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0d40), mload(0x0d60))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0d00), mload(0x0d20))
                    for
                        {
                            let mptr := 0x04e4
                            let mptr_end := 0x0164
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0124
                            let mptr_end := 0x24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    mstore(0x80, calldataload(0x0164))
                    mstore(0xa0, calldataload(0x0184))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0440), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x0524))
                    mstore(0xa0, calldataload(0x0544))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0460), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x08a4))
                    mstore(0xa0, calldataload(0x08c4))
                    for
                        {
                            let mptr := 0x0864
                            let mptr_end := 0x0524
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0480), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(R, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x1564))
                    mstore(0xa0, calldataload(0x1584))
                    success := ec_mul_tmp(success, sub(R, mload(0x0400)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x15a4))
                    mstore(0xa0, calldataload(0x15c4))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x15a4))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x15c4))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}