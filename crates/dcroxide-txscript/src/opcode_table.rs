// SPDX-License-Identifier: ISC
// GENERATED from dcrd txscript/opcode.go's opcodeArray at release-v2.1.5;
// regenerate with the script in the commit that introduced it rather than
// editing by hand. Handlers live in opcodes.rs.
//! Opcode constants and the 256-entry dispatch table (dcrd `opcodeArray`).

use crate::opcodes::*;

/// The `OP_0` opcode (0x00).
pub const OP_0: u8 = 0x00;
/// The `OP_DATA_1` opcode (0x01).
pub const OP_DATA_1: u8 = 0x01;
/// The `OP_DATA_2` opcode (0x02).
pub const OP_DATA_2: u8 = 0x02;
/// The `OP_DATA_3` opcode (0x03).
pub const OP_DATA_3: u8 = 0x03;
/// The `OP_DATA_4` opcode (0x04).
pub const OP_DATA_4: u8 = 0x04;
/// The `OP_DATA_5` opcode (0x05).
pub const OP_DATA_5: u8 = 0x05;
/// The `OP_DATA_6` opcode (0x06).
pub const OP_DATA_6: u8 = 0x06;
/// The `OP_DATA_7` opcode (0x07).
pub const OP_DATA_7: u8 = 0x07;
/// The `OP_DATA_8` opcode (0x08).
pub const OP_DATA_8: u8 = 0x08;
/// The `OP_DATA_9` opcode (0x09).
pub const OP_DATA_9: u8 = 0x09;
/// The `OP_DATA_10` opcode (0x0a).
pub const OP_DATA_10: u8 = 0x0a;
/// The `OP_DATA_11` opcode (0x0b).
pub const OP_DATA_11: u8 = 0x0b;
/// The `OP_DATA_12` opcode (0x0c).
pub const OP_DATA_12: u8 = 0x0c;
/// The `OP_DATA_13` opcode (0x0d).
pub const OP_DATA_13: u8 = 0x0d;
/// The `OP_DATA_14` opcode (0x0e).
pub const OP_DATA_14: u8 = 0x0e;
/// The `OP_DATA_15` opcode (0x0f).
pub const OP_DATA_15: u8 = 0x0f;
/// The `OP_DATA_16` opcode (0x10).
pub const OP_DATA_16: u8 = 0x10;
/// The `OP_DATA_17` opcode (0x11).
pub const OP_DATA_17: u8 = 0x11;
/// The `OP_DATA_18` opcode (0x12).
pub const OP_DATA_18: u8 = 0x12;
/// The `OP_DATA_19` opcode (0x13).
pub const OP_DATA_19: u8 = 0x13;
/// The `OP_DATA_20` opcode (0x14).
pub const OP_DATA_20: u8 = 0x14;
/// The `OP_DATA_21` opcode (0x15).
pub const OP_DATA_21: u8 = 0x15;
/// The `OP_DATA_22` opcode (0x16).
pub const OP_DATA_22: u8 = 0x16;
/// The `OP_DATA_23` opcode (0x17).
pub const OP_DATA_23: u8 = 0x17;
/// The `OP_DATA_24` opcode (0x18).
pub const OP_DATA_24: u8 = 0x18;
/// The `OP_DATA_25` opcode (0x19).
pub const OP_DATA_25: u8 = 0x19;
/// The `OP_DATA_26` opcode (0x1a).
pub const OP_DATA_26: u8 = 0x1a;
/// The `OP_DATA_27` opcode (0x1b).
pub const OP_DATA_27: u8 = 0x1b;
/// The `OP_DATA_28` opcode (0x1c).
pub const OP_DATA_28: u8 = 0x1c;
/// The `OP_DATA_29` opcode (0x1d).
pub const OP_DATA_29: u8 = 0x1d;
/// The `OP_DATA_30` opcode (0x1e).
pub const OP_DATA_30: u8 = 0x1e;
/// The `OP_DATA_31` opcode (0x1f).
pub const OP_DATA_31: u8 = 0x1f;
/// The `OP_DATA_32` opcode (0x20).
pub const OP_DATA_32: u8 = 0x20;
/// The `OP_DATA_33` opcode (0x21).
pub const OP_DATA_33: u8 = 0x21;
/// The `OP_DATA_34` opcode (0x22).
pub const OP_DATA_34: u8 = 0x22;
/// The `OP_DATA_35` opcode (0x23).
pub const OP_DATA_35: u8 = 0x23;
/// The `OP_DATA_36` opcode (0x24).
pub const OP_DATA_36: u8 = 0x24;
/// The `OP_DATA_37` opcode (0x25).
pub const OP_DATA_37: u8 = 0x25;
/// The `OP_DATA_38` opcode (0x26).
pub const OP_DATA_38: u8 = 0x26;
/// The `OP_DATA_39` opcode (0x27).
pub const OP_DATA_39: u8 = 0x27;
/// The `OP_DATA_40` opcode (0x28).
pub const OP_DATA_40: u8 = 0x28;
/// The `OP_DATA_41` opcode (0x29).
pub const OP_DATA_41: u8 = 0x29;
/// The `OP_DATA_42` opcode (0x2a).
pub const OP_DATA_42: u8 = 0x2a;
/// The `OP_DATA_43` opcode (0x2b).
pub const OP_DATA_43: u8 = 0x2b;
/// The `OP_DATA_44` opcode (0x2c).
pub const OP_DATA_44: u8 = 0x2c;
/// The `OP_DATA_45` opcode (0x2d).
pub const OP_DATA_45: u8 = 0x2d;
/// The `OP_DATA_46` opcode (0x2e).
pub const OP_DATA_46: u8 = 0x2e;
/// The `OP_DATA_47` opcode (0x2f).
pub const OP_DATA_47: u8 = 0x2f;
/// The `OP_DATA_48` opcode (0x30).
pub const OP_DATA_48: u8 = 0x30;
/// The `OP_DATA_49` opcode (0x31).
pub const OP_DATA_49: u8 = 0x31;
/// The `OP_DATA_50` opcode (0x32).
pub const OP_DATA_50: u8 = 0x32;
/// The `OP_DATA_51` opcode (0x33).
pub const OP_DATA_51: u8 = 0x33;
/// The `OP_DATA_52` opcode (0x34).
pub const OP_DATA_52: u8 = 0x34;
/// The `OP_DATA_53` opcode (0x35).
pub const OP_DATA_53: u8 = 0x35;
/// The `OP_DATA_54` opcode (0x36).
pub const OP_DATA_54: u8 = 0x36;
/// The `OP_DATA_55` opcode (0x37).
pub const OP_DATA_55: u8 = 0x37;
/// The `OP_DATA_56` opcode (0x38).
pub const OP_DATA_56: u8 = 0x38;
/// The `OP_DATA_57` opcode (0x39).
pub const OP_DATA_57: u8 = 0x39;
/// The `OP_DATA_58` opcode (0x3a).
pub const OP_DATA_58: u8 = 0x3a;
/// The `OP_DATA_59` opcode (0x3b).
pub const OP_DATA_59: u8 = 0x3b;
/// The `OP_DATA_60` opcode (0x3c).
pub const OP_DATA_60: u8 = 0x3c;
/// The `OP_DATA_61` opcode (0x3d).
pub const OP_DATA_61: u8 = 0x3d;
/// The `OP_DATA_62` opcode (0x3e).
pub const OP_DATA_62: u8 = 0x3e;
/// The `OP_DATA_63` opcode (0x3f).
pub const OP_DATA_63: u8 = 0x3f;
/// The `OP_DATA_64` opcode (0x40).
pub const OP_DATA_64: u8 = 0x40;
/// The `OP_DATA_65` opcode (0x41).
pub const OP_DATA_65: u8 = 0x41;
/// The `OP_DATA_66` opcode (0x42).
pub const OP_DATA_66: u8 = 0x42;
/// The `OP_DATA_67` opcode (0x43).
pub const OP_DATA_67: u8 = 0x43;
/// The `OP_DATA_68` opcode (0x44).
pub const OP_DATA_68: u8 = 0x44;
/// The `OP_DATA_69` opcode (0x45).
pub const OP_DATA_69: u8 = 0x45;
/// The `OP_DATA_70` opcode (0x46).
pub const OP_DATA_70: u8 = 0x46;
/// The `OP_DATA_71` opcode (0x47).
pub const OP_DATA_71: u8 = 0x47;
/// The `OP_DATA_72` opcode (0x48).
pub const OP_DATA_72: u8 = 0x48;
/// The `OP_DATA_73` opcode (0x49).
pub const OP_DATA_73: u8 = 0x49;
/// The `OP_DATA_74` opcode (0x4a).
pub const OP_DATA_74: u8 = 0x4a;
/// The `OP_DATA_75` opcode (0x4b).
pub const OP_DATA_75: u8 = 0x4b;
/// The `OP_PUSHDATA1` opcode (0x4c).
pub const OP_PUSHDATA1: u8 = 0x4c;
/// The `OP_PUSHDATA2` opcode (0x4d).
pub const OP_PUSHDATA2: u8 = 0x4d;
/// The `OP_PUSHDATA4` opcode (0x4e).
pub const OP_PUSHDATA4: u8 = 0x4e;
/// The `OP_1NEGATE` opcode (0x4f).
pub const OP_1NEGATE: u8 = 0x4f;
/// The `OP_RESERVED` opcode (0x50).
pub const OP_RESERVED: u8 = 0x50;
/// The `OP_1` opcode (0x51).
pub const OP_1: u8 = 0x51;
/// The `OP_2` opcode (0x52).
pub const OP_2: u8 = 0x52;
/// The `OP_3` opcode (0x53).
pub const OP_3: u8 = 0x53;
/// The `OP_4` opcode (0x54).
pub const OP_4: u8 = 0x54;
/// The `OP_5` opcode (0x55).
pub const OP_5: u8 = 0x55;
/// The `OP_6` opcode (0x56).
pub const OP_6: u8 = 0x56;
/// The `OP_7` opcode (0x57).
pub const OP_7: u8 = 0x57;
/// The `OP_8` opcode (0x58).
pub const OP_8: u8 = 0x58;
/// The `OP_9` opcode (0x59).
pub const OP_9: u8 = 0x59;
/// The `OP_10` opcode (0x5a).
pub const OP_10: u8 = 0x5a;
/// The `OP_11` opcode (0x5b).
pub const OP_11: u8 = 0x5b;
/// The `OP_12` opcode (0x5c).
pub const OP_12: u8 = 0x5c;
/// The `OP_13` opcode (0x5d).
pub const OP_13: u8 = 0x5d;
/// The `OP_14` opcode (0x5e).
pub const OP_14: u8 = 0x5e;
/// The `OP_15` opcode (0x5f).
pub const OP_15: u8 = 0x5f;
/// The `OP_16` opcode (0x60).
pub const OP_16: u8 = 0x60;
/// The `OP_NOP` opcode (0x61).
pub const OP_NOP: u8 = 0x61;
/// The `OP_VER` opcode (0x62).
pub const OP_VER: u8 = 0x62;
/// The `OP_IF` opcode (0x63).
pub const OP_IF: u8 = 0x63;
/// The `OP_NOTIF` opcode (0x64).
pub const OP_NOTIF: u8 = 0x64;
/// The `OP_VERIF` opcode (0x65).
pub const OP_VERIF: u8 = 0x65;
/// The `OP_VERNOTIF` opcode (0x66).
pub const OP_VERNOTIF: u8 = 0x66;
/// The `OP_ELSE` opcode (0x67).
pub const OP_ELSE: u8 = 0x67;
/// The `OP_ENDIF` opcode (0x68).
pub const OP_ENDIF: u8 = 0x68;
/// The `OP_VERIFY` opcode (0x69).
pub const OP_VERIFY: u8 = 0x69;
/// The `OP_RETURN` opcode (0x6a).
pub const OP_RETURN: u8 = 0x6a;
/// The `OP_TOALTSTACK` opcode (0x6b).
pub const OP_TOALTSTACK: u8 = 0x6b;
/// The `OP_FROMALTSTACK` opcode (0x6c).
pub const OP_FROMALTSTACK: u8 = 0x6c;
/// The `OP_2DROP` opcode (0x6d).
pub const OP_2DROP: u8 = 0x6d;
/// The `OP_2DUP` opcode (0x6e).
pub const OP_2DUP: u8 = 0x6e;
/// The `OP_3DUP` opcode (0x6f).
pub const OP_3DUP: u8 = 0x6f;
/// The `OP_2OVER` opcode (0x70).
pub const OP_2OVER: u8 = 0x70;
/// The `OP_2ROT` opcode (0x71).
pub const OP_2ROT: u8 = 0x71;
/// The `OP_2SWAP` opcode (0x72).
pub const OP_2SWAP: u8 = 0x72;
/// The `OP_IFDUP` opcode (0x73).
pub const OP_IFDUP: u8 = 0x73;
/// The `OP_DEPTH` opcode (0x74).
pub const OP_DEPTH: u8 = 0x74;
/// The `OP_DROP` opcode (0x75).
pub const OP_DROP: u8 = 0x75;
/// The `OP_DUP` opcode (0x76).
pub const OP_DUP: u8 = 0x76;
/// The `OP_NIP` opcode (0x77).
pub const OP_NIP: u8 = 0x77;
/// The `OP_OVER` opcode (0x78).
pub const OP_OVER: u8 = 0x78;
/// The `OP_PICK` opcode (0x79).
pub const OP_PICK: u8 = 0x79;
/// The `OP_ROLL` opcode (0x7a).
pub const OP_ROLL: u8 = 0x7a;
/// The `OP_ROT` opcode (0x7b).
pub const OP_ROT: u8 = 0x7b;
/// The `OP_SWAP` opcode (0x7c).
pub const OP_SWAP: u8 = 0x7c;
/// The `OP_TUCK` opcode (0x7d).
pub const OP_TUCK: u8 = 0x7d;
/// The `OP_CAT` opcode (0x7e).
pub const OP_CAT: u8 = 0x7e;
/// The `OP_SUBSTR` opcode (0x7f).
pub const OP_SUBSTR: u8 = 0x7f;
/// The `OP_LEFT` opcode (0x80).
pub const OP_LEFT: u8 = 0x80;
/// The `OP_RIGHT` opcode (0x81).
pub const OP_RIGHT: u8 = 0x81;
/// The `OP_SIZE` opcode (0x82).
pub const OP_SIZE: u8 = 0x82;
/// The `OP_INVERT` opcode (0x83).
pub const OP_INVERT: u8 = 0x83;
/// The `OP_AND` opcode (0x84).
pub const OP_AND: u8 = 0x84;
/// The `OP_OR` opcode (0x85).
pub const OP_OR: u8 = 0x85;
/// The `OP_XOR` opcode (0x86).
pub const OP_XOR: u8 = 0x86;
/// The `OP_EQUAL` opcode (0x87).
pub const OP_EQUAL: u8 = 0x87;
/// The `OP_EQUALVERIFY` opcode (0x88).
pub const OP_EQUALVERIFY: u8 = 0x88;
/// The `OP_ROTR` opcode (0x89).
pub const OP_ROTR: u8 = 0x89;
/// The `OP_ROTL` opcode (0x8a).
pub const OP_ROTL: u8 = 0x8a;
/// The `OP_1ADD` opcode (0x8b).
pub const OP_1ADD: u8 = 0x8b;
/// The `OP_1SUB` opcode (0x8c).
pub const OP_1SUB: u8 = 0x8c;
/// The `OP_2MUL` opcode (0x8d).
pub const OP_2MUL: u8 = 0x8d;
/// The `OP_2DIV` opcode (0x8e).
pub const OP_2DIV: u8 = 0x8e;
/// The `OP_NEGATE` opcode (0x8f).
pub const OP_NEGATE: u8 = 0x8f;
/// The `OP_ABS` opcode (0x90).
pub const OP_ABS: u8 = 0x90;
/// The `OP_NOT` opcode (0x91).
pub const OP_NOT: u8 = 0x91;
/// The `OP_0NOTEQUAL` opcode (0x92).
pub const OP_0NOTEQUAL: u8 = 0x92;
/// The `OP_ADD` opcode (0x93).
pub const OP_ADD: u8 = 0x93;
/// The `OP_SUB` opcode (0x94).
pub const OP_SUB: u8 = 0x94;
/// The `OP_MUL` opcode (0x95).
pub const OP_MUL: u8 = 0x95;
/// The `OP_DIV` opcode (0x96).
pub const OP_DIV: u8 = 0x96;
/// The `OP_MOD` opcode (0x97).
pub const OP_MOD: u8 = 0x97;
/// The `OP_LSHIFT` opcode (0x98).
pub const OP_LSHIFT: u8 = 0x98;
/// The `OP_RSHIFT` opcode (0x99).
pub const OP_RSHIFT: u8 = 0x99;
/// The `OP_BOOLAND` opcode (0x9a).
pub const OP_BOOLAND: u8 = 0x9a;
/// The `OP_BOOLOR` opcode (0x9b).
pub const OP_BOOLOR: u8 = 0x9b;
/// The `OP_NUMEQUAL` opcode (0x9c).
pub const OP_NUMEQUAL: u8 = 0x9c;
/// The `OP_NUMEQUALVERIFY` opcode (0x9d).
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
/// The `OP_NUMNOTEQUAL` opcode (0x9e).
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
/// The `OP_LESSTHAN` opcode (0x9f).
pub const OP_LESSTHAN: u8 = 0x9f;
/// The `OP_GREATERTHAN` opcode (0xa0).
pub const OP_GREATERTHAN: u8 = 0xa0;
/// The `OP_LESSTHANOREQUAL` opcode (0xa1).
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
/// The `OP_GREATERTHANOREQUAL` opcode (0xa2).
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
/// The `OP_MIN` opcode (0xa3).
pub const OP_MIN: u8 = 0xa3;
/// The `OP_MAX` opcode (0xa4).
pub const OP_MAX: u8 = 0xa4;
/// The `OP_WITHIN` opcode (0xa5).
pub const OP_WITHIN: u8 = 0xa5;
/// The `OP_RIPEMD160` opcode (0xa6).
pub const OP_RIPEMD160: u8 = 0xa6;
/// The `OP_SHA1` opcode (0xa7).
pub const OP_SHA1: u8 = 0xa7;
/// The `OP_BLAKE256` opcode (0xa8).
pub const OP_BLAKE256: u8 = 0xa8;
/// The `OP_HASH160` opcode (0xa9).
pub const OP_HASH160: u8 = 0xa9;
/// The `OP_HASH256` opcode (0xaa).
pub const OP_HASH256: u8 = 0xaa;
/// The `OP_CODESEPARATOR` opcode (0xab).
pub const OP_CODESEPARATOR: u8 = 0xab;
/// The `OP_CHECKSIG` opcode (0xac).
pub const OP_CHECKSIG: u8 = 0xac;
/// The `OP_CHECKSIGVERIFY` opcode (0xad).
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
/// The `OP_CHECKMULTISIG` opcode (0xae).
pub const OP_CHECKMULTISIG: u8 = 0xae;
/// The `OP_CHECKMULTISIGVERIFY` opcode (0xaf).
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
/// The `OP_NOP1` opcode (0xb0).
pub const OP_NOP1: u8 = 0xb0;
/// The `OP_CHECKLOCKTIMEVERIFY` opcode (0xb1).
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
/// The `OP_CHECKSEQUENCEVERIFY` opcode (0xb2).
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
/// The `OP_NOP4` opcode (0xb3).
pub const OP_NOP4: u8 = 0xb3;
/// The `OP_NOP5` opcode (0xb4).
pub const OP_NOP5: u8 = 0xb4;
/// The `OP_NOP6` opcode (0xb5).
pub const OP_NOP6: u8 = 0xb5;
/// The `OP_NOP7` opcode (0xb6).
pub const OP_NOP7: u8 = 0xb6;
/// The `OP_NOP8` opcode (0xb7).
pub const OP_NOP8: u8 = 0xb7;
/// The `OP_NOP9` opcode (0xb8).
pub const OP_NOP9: u8 = 0xb8;
/// The `OP_NOP10` opcode (0xb9).
pub const OP_NOP10: u8 = 0xb9;
/// The `OP_SSTX` opcode (0xba).
pub const OP_SSTX: u8 = 0xba;
/// The `OP_SSGEN` opcode (0xbb).
pub const OP_SSGEN: u8 = 0xbb;
/// The `OP_SSRTX` opcode (0xbc).
pub const OP_SSRTX: u8 = 0xbc;
/// The `OP_SSTXCHANGE` opcode (0xbd).
pub const OP_SSTXCHANGE: u8 = 0xbd;
/// The `OP_CHECKSIGALT` opcode (0xbe).
pub const OP_CHECKSIGALT: u8 = 0xbe;
/// The `OP_CHECKSIGALTVERIFY` opcode (0xbf).
pub const OP_CHECKSIGALTVERIFY: u8 = 0xbf;
/// The `OP_SHA256` opcode (0xc0).
pub const OP_SHA256: u8 = 0xc0;
/// The `OP_TADD` opcode (0xc1).
pub const OP_TADD: u8 = 0xc1;
/// The `OP_TSPEND` opcode (0xc2).
pub const OP_TSPEND: u8 = 0xc2;
/// The `OP_TGEN` opcode (0xc3).
pub const OP_TGEN: u8 = 0xc3;
/// The `OP_UNKNOWN196` opcode (0xc4).
pub const OP_UNKNOWN196: u8 = 0xc4;
/// The `OP_UNKNOWN197` opcode (0xc5).
pub const OP_UNKNOWN197: u8 = 0xc5;
/// The `OP_UNKNOWN198` opcode (0xc6).
pub const OP_UNKNOWN198: u8 = 0xc6;
/// The `OP_UNKNOWN199` opcode (0xc7).
pub const OP_UNKNOWN199: u8 = 0xc7;
/// The `OP_UNKNOWN200` opcode (0xc8).
pub const OP_UNKNOWN200: u8 = 0xc8;
/// The `OP_UNKNOWN201` opcode (0xc9).
pub const OP_UNKNOWN201: u8 = 0xc9;
/// The `OP_UNKNOWN202` opcode (0xca).
pub const OP_UNKNOWN202: u8 = 0xca;
/// The `OP_UNKNOWN203` opcode (0xcb).
pub const OP_UNKNOWN203: u8 = 0xcb;
/// The `OP_UNKNOWN204` opcode (0xcc).
pub const OP_UNKNOWN204: u8 = 0xcc;
/// The `OP_UNKNOWN205` opcode (0xcd).
pub const OP_UNKNOWN205: u8 = 0xcd;
/// The `OP_UNKNOWN206` opcode (0xce).
pub const OP_UNKNOWN206: u8 = 0xce;
/// The `OP_UNKNOWN207` opcode (0xcf).
pub const OP_UNKNOWN207: u8 = 0xcf;
/// The `OP_UNKNOWN208` opcode (0xd0).
pub const OP_UNKNOWN208: u8 = 0xd0;
/// The `OP_UNKNOWN209` opcode (0xd1).
pub const OP_UNKNOWN209: u8 = 0xd1;
/// The `OP_UNKNOWN210` opcode (0xd2).
pub const OP_UNKNOWN210: u8 = 0xd2;
/// The `OP_UNKNOWN211` opcode (0xd3).
pub const OP_UNKNOWN211: u8 = 0xd3;
/// The `OP_UNKNOWN212` opcode (0xd4).
pub const OP_UNKNOWN212: u8 = 0xd4;
/// The `OP_UNKNOWN213` opcode (0xd5).
pub const OP_UNKNOWN213: u8 = 0xd5;
/// The `OP_UNKNOWN214` opcode (0xd6).
pub const OP_UNKNOWN214: u8 = 0xd6;
/// The `OP_UNKNOWN215` opcode (0xd7).
pub const OP_UNKNOWN215: u8 = 0xd7;
/// The `OP_UNKNOWN216` opcode (0xd8).
pub const OP_UNKNOWN216: u8 = 0xd8;
/// The `OP_UNKNOWN217` opcode (0xd9).
pub const OP_UNKNOWN217: u8 = 0xd9;
/// The `OP_UNKNOWN218` opcode (0xda).
pub const OP_UNKNOWN218: u8 = 0xda;
/// The `OP_UNKNOWN219` opcode (0xdb).
pub const OP_UNKNOWN219: u8 = 0xdb;
/// The `OP_UNKNOWN220` opcode (0xdc).
pub const OP_UNKNOWN220: u8 = 0xdc;
/// The `OP_UNKNOWN221` opcode (0xdd).
pub const OP_UNKNOWN221: u8 = 0xdd;
/// The `OP_UNKNOWN222` opcode (0xde).
pub const OP_UNKNOWN222: u8 = 0xde;
/// The `OP_UNKNOWN223` opcode (0xdf).
pub const OP_UNKNOWN223: u8 = 0xdf;
/// The `OP_UNKNOWN224` opcode (0xe0).
pub const OP_UNKNOWN224: u8 = 0xe0;
/// The `OP_UNKNOWN225` opcode (0xe1).
pub const OP_UNKNOWN225: u8 = 0xe1;
/// The `OP_UNKNOWN226` opcode (0xe2).
pub const OP_UNKNOWN226: u8 = 0xe2;
/// The `OP_UNKNOWN227` opcode (0xe3).
pub const OP_UNKNOWN227: u8 = 0xe3;
/// The `OP_UNKNOWN228` opcode (0xe4).
pub const OP_UNKNOWN228: u8 = 0xe4;
/// The `OP_UNKNOWN229` opcode (0xe5).
pub const OP_UNKNOWN229: u8 = 0xe5;
/// The `OP_UNKNOWN230` opcode (0xe6).
pub const OP_UNKNOWN230: u8 = 0xe6;
/// The `OP_UNKNOWN231` opcode (0xe7).
pub const OP_UNKNOWN231: u8 = 0xe7;
/// The `OP_UNKNOWN232` opcode (0xe8).
pub const OP_UNKNOWN232: u8 = 0xe8;
/// The `OP_UNKNOWN233` opcode (0xe9).
pub const OP_UNKNOWN233: u8 = 0xe9;
/// The `OP_UNKNOWN234` opcode (0xea).
pub const OP_UNKNOWN234: u8 = 0xea;
/// The `OP_UNKNOWN235` opcode (0xeb).
pub const OP_UNKNOWN235: u8 = 0xeb;
/// The `OP_UNKNOWN236` opcode (0xec).
pub const OP_UNKNOWN236: u8 = 0xec;
/// The `OP_UNKNOWN237` opcode (0xed).
pub const OP_UNKNOWN237: u8 = 0xed;
/// The `OP_UNKNOWN238` opcode (0xee).
pub const OP_UNKNOWN238: u8 = 0xee;
/// The `OP_UNKNOWN239` opcode (0xef).
pub const OP_UNKNOWN239: u8 = 0xef;
/// The `OP_UNKNOWN240` opcode (0xf0).
pub const OP_UNKNOWN240: u8 = 0xf0;
/// The `OP_UNKNOWN241` opcode (0xf1).
pub const OP_UNKNOWN241: u8 = 0xf1;
/// The `OP_UNKNOWN242` opcode (0xf2).
pub const OP_UNKNOWN242: u8 = 0xf2;
/// The `OP_UNKNOWN243` opcode (0xf3).
pub const OP_UNKNOWN243: u8 = 0xf3;
/// The `OP_UNKNOWN244` opcode (0xf4).
pub const OP_UNKNOWN244: u8 = 0xf4;
/// The `OP_UNKNOWN245` opcode (0xf5).
pub const OP_UNKNOWN245: u8 = 0xf5;
/// The `OP_UNKNOWN246` opcode (0xf6).
pub const OP_UNKNOWN246: u8 = 0xf6;
/// The `OP_UNKNOWN247` opcode (0xf7).
pub const OP_UNKNOWN247: u8 = 0xf7;
/// The `OP_UNKNOWN248` opcode (0xf8).
pub const OP_UNKNOWN248: u8 = 0xf8;
/// The `OP_INVALID249` opcode (0xf9).
pub const OP_INVALID249: u8 = 0xf9;
/// The `OP_SMALLINTEGER` opcode (0xfa).
pub const OP_SMALLINTEGER: u8 = 0xfa;
/// The `OP_PUBKEYS` opcode (0xfb).
pub const OP_PUBKEYS: u8 = 0xfb;
/// The `OP_UNKNOWN252` opcode (0xfc).
pub const OP_UNKNOWN252: u8 = 0xfc;
/// The `OP_PUBKEYHASH` opcode (0xfd).
pub const OP_PUBKEYHASH: u8 = 0xfd;
/// The `OP_PUBKEY` opcode (0xfe).
pub const OP_PUBKEY: u8 = 0xfe;
/// The `OP_INVALIDOPCODE` opcode (0xff).
pub const OP_INVALIDOPCODE: u8 = 0xff;

/// `OP_0` alias (dcrd `OP_FALSE`).
pub const OP_FALSE: u8 = OP_0;
/// `OP_1` alias (dcrd `OP_TRUE`).
pub const OP_TRUE: u8 = OP_1;
/// `OP_CHECKLOCKTIMEVERIFY` alias (dcrd `OP_NOP2`).
pub const OP_NOP2: u8 = OP_CHECKLOCKTIMEVERIFY;
/// `OP_CHECKSEQUENCEVERIFY` alias (dcrd `OP_NOP3`).
pub const OP_NOP3: u8 = OP_CHECKSEQUENCEVERIFY;

/// Details about all 256 opcodes (dcrd `opcodeArray`): value, name,
/// length semantics, and execution handler.
pub(crate) static OPCODE_ARRAY: [OpcodeInfo; 256] = [
    OpcodeInfo {
        value: OP_0,
        name: "OP_0",
        length: 1,
        func: opcode_false,
    },
    OpcodeInfo {
        value: OP_DATA_1,
        name: "OP_DATA_1",
        length: 2,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_2,
        name: "OP_DATA_2",
        length: 3,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_3,
        name: "OP_DATA_3",
        length: 4,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_4,
        name: "OP_DATA_4",
        length: 5,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_5,
        name: "OP_DATA_5",
        length: 6,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_6,
        name: "OP_DATA_6",
        length: 7,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_7,
        name: "OP_DATA_7",
        length: 8,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_8,
        name: "OP_DATA_8",
        length: 9,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_9,
        name: "OP_DATA_9",
        length: 10,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_10,
        name: "OP_DATA_10",
        length: 11,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_11,
        name: "OP_DATA_11",
        length: 12,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_12,
        name: "OP_DATA_12",
        length: 13,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_13,
        name: "OP_DATA_13",
        length: 14,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_14,
        name: "OP_DATA_14",
        length: 15,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_15,
        name: "OP_DATA_15",
        length: 16,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_16,
        name: "OP_DATA_16",
        length: 17,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_17,
        name: "OP_DATA_17",
        length: 18,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_18,
        name: "OP_DATA_18",
        length: 19,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_19,
        name: "OP_DATA_19",
        length: 20,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_20,
        name: "OP_DATA_20",
        length: 21,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_21,
        name: "OP_DATA_21",
        length: 22,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_22,
        name: "OP_DATA_22",
        length: 23,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_23,
        name: "OP_DATA_23",
        length: 24,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_24,
        name: "OP_DATA_24",
        length: 25,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_25,
        name: "OP_DATA_25",
        length: 26,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_26,
        name: "OP_DATA_26",
        length: 27,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_27,
        name: "OP_DATA_27",
        length: 28,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_28,
        name: "OP_DATA_28",
        length: 29,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_29,
        name: "OP_DATA_29",
        length: 30,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_30,
        name: "OP_DATA_30",
        length: 31,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_31,
        name: "OP_DATA_31",
        length: 32,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_32,
        name: "OP_DATA_32",
        length: 33,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_33,
        name: "OP_DATA_33",
        length: 34,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_34,
        name: "OP_DATA_34",
        length: 35,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_35,
        name: "OP_DATA_35",
        length: 36,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_36,
        name: "OP_DATA_36",
        length: 37,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_37,
        name: "OP_DATA_37",
        length: 38,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_38,
        name: "OP_DATA_38",
        length: 39,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_39,
        name: "OP_DATA_39",
        length: 40,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_40,
        name: "OP_DATA_40",
        length: 41,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_41,
        name: "OP_DATA_41",
        length: 42,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_42,
        name: "OP_DATA_42",
        length: 43,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_43,
        name: "OP_DATA_43",
        length: 44,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_44,
        name: "OP_DATA_44",
        length: 45,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_45,
        name: "OP_DATA_45",
        length: 46,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_46,
        name: "OP_DATA_46",
        length: 47,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_47,
        name: "OP_DATA_47",
        length: 48,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_48,
        name: "OP_DATA_48",
        length: 49,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_49,
        name: "OP_DATA_49",
        length: 50,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_50,
        name: "OP_DATA_50",
        length: 51,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_51,
        name: "OP_DATA_51",
        length: 52,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_52,
        name: "OP_DATA_52",
        length: 53,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_53,
        name: "OP_DATA_53",
        length: 54,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_54,
        name: "OP_DATA_54",
        length: 55,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_55,
        name: "OP_DATA_55",
        length: 56,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_56,
        name: "OP_DATA_56",
        length: 57,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_57,
        name: "OP_DATA_57",
        length: 58,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_58,
        name: "OP_DATA_58",
        length: 59,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_59,
        name: "OP_DATA_59",
        length: 60,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_60,
        name: "OP_DATA_60",
        length: 61,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_61,
        name: "OP_DATA_61",
        length: 62,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_62,
        name: "OP_DATA_62",
        length: 63,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_63,
        name: "OP_DATA_63",
        length: 64,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_64,
        name: "OP_DATA_64",
        length: 65,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_65,
        name: "OP_DATA_65",
        length: 66,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_66,
        name: "OP_DATA_66",
        length: 67,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_67,
        name: "OP_DATA_67",
        length: 68,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_68,
        name: "OP_DATA_68",
        length: 69,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_69,
        name: "OP_DATA_69",
        length: 70,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_70,
        name: "OP_DATA_70",
        length: 71,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_71,
        name: "OP_DATA_71",
        length: 72,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_72,
        name: "OP_DATA_72",
        length: 73,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_73,
        name: "OP_DATA_73",
        length: 74,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_74,
        name: "OP_DATA_74",
        length: 75,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_DATA_75,
        name: "OP_DATA_75",
        length: 76,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_PUSHDATA1,
        name: "OP_PUSHDATA1",
        length: -1,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_PUSHDATA2,
        name: "OP_PUSHDATA2",
        length: -2,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_PUSHDATA4,
        name: "OP_PUSHDATA4",
        length: -4,
        func: opcode_push_data,
    },
    OpcodeInfo {
        value: OP_1NEGATE,
        name: "OP_1NEGATE",
        length: 1,
        func: opcode_1negate,
    },
    OpcodeInfo {
        value: OP_RESERVED,
        name: "OP_RESERVED",
        length: 1,
        func: opcode_reserved,
    },
    OpcodeInfo {
        value: OP_1,
        name: "OP_1",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_2,
        name: "OP_2",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_3,
        name: "OP_3",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_4,
        name: "OP_4",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_5,
        name: "OP_5",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_6,
        name: "OP_6",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_7,
        name: "OP_7",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_8,
        name: "OP_8",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_9,
        name: "OP_9",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_10,
        name: "OP_10",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_11,
        name: "OP_11",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_12,
        name: "OP_12",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_13,
        name: "OP_13",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_14,
        name: "OP_14",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_15,
        name: "OP_15",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_16,
        name: "OP_16",
        length: 1,
        func: opcode_n,
    },
    OpcodeInfo {
        value: OP_NOP,
        name: "OP_NOP",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_VER,
        name: "OP_VER",
        length: 1,
        func: opcode_reserved,
    },
    OpcodeInfo {
        value: OP_IF,
        name: "OP_IF",
        length: 1,
        func: opcode_if,
    },
    OpcodeInfo {
        value: OP_NOTIF,
        name: "OP_NOTIF",
        length: 1,
        func: opcode_notif,
    },
    OpcodeInfo {
        value: OP_VERIF,
        name: "OP_VERIF",
        length: 1,
        func: opcode_reserved,
    },
    OpcodeInfo {
        value: OP_VERNOTIF,
        name: "OP_VERNOTIF",
        length: 1,
        func: opcode_reserved,
    },
    OpcodeInfo {
        value: OP_ELSE,
        name: "OP_ELSE",
        length: 1,
        func: opcode_else,
    },
    OpcodeInfo {
        value: OP_ENDIF,
        name: "OP_ENDIF",
        length: 1,
        func: opcode_endif,
    },
    OpcodeInfo {
        value: OP_VERIFY,
        name: "OP_VERIFY",
        length: 1,
        func: opcode_verify,
    },
    OpcodeInfo {
        value: OP_RETURN,
        name: "OP_RETURN",
        length: 1,
        func: opcode_return,
    },
    OpcodeInfo {
        value: OP_TOALTSTACK,
        name: "OP_TOALTSTACK",
        length: 1,
        func: opcode_to_alt_stack,
    },
    OpcodeInfo {
        value: OP_FROMALTSTACK,
        name: "OP_FROMALTSTACK",
        length: 1,
        func: opcode_from_alt_stack,
    },
    OpcodeInfo {
        value: OP_2DROP,
        name: "OP_2DROP",
        length: 1,
        func: opcode_2drop,
    },
    OpcodeInfo {
        value: OP_2DUP,
        name: "OP_2DUP",
        length: 1,
        func: opcode_2dup,
    },
    OpcodeInfo {
        value: OP_3DUP,
        name: "OP_3DUP",
        length: 1,
        func: opcode_3dup,
    },
    OpcodeInfo {
        value: OP_2OVER,
        name: "OP_2OVER",
        length: 1,
        func: opcode_2over,
    },
    OpcodeInfo {
        value: OP_2ROT,
        name: "OP_2ROT",
        length: 1,
        func: opcode_2rot,
    },
    OpcodeInfo {
        value: OP_2SWAP,
        name: "OP_2SWAP",
        length: 1,
        func: opcode_2swap,
    },
    OpcodeInfo {
        value: OP_IFDUP,
        name: "OP_IFDUP",
        length: 1,
        func: opcode_if_dup,
    },
    OpcodeInfo {
        value: OP_DEPTH,
        name: "OP_DEPTH",
        length: 1,
        func: opcode_depth,
    },
    OpcodeInfo {
        value: OP_DROP,
        name: "OP_DROP",
        length: 1,
        func: opcode_drop,
    },
    OpcodeInfo {
        value: OP_DUP,
        name: "OP_DUP",
        length: 1,
        func: opcode_dup,
    },
    OpcodeInfo {
        value: OP_NIP,
        name: "OP_NIP",
        length: 1,
        func: opcode_nip,
    },
    OpcodeInfo {
        value: OP_OVER,
        name: "OP_OVER",
        length: 1,
        func: opcode_over,
    },
    OpcodeInfo {
        value: OP_PICK,
        name: "OP_PICK",
        length: 1,
        func: opcode_pick,
    },
    OpcodeInfo {
        value: OP_ROLL,
        name: "OP_ROLL",
        length: 1,
        func: opcode_roll,
    },
    OpcodeInfo {
        value: OP_ROT,
        name: "OP_ROT",
        length: 1,
        func: opcode_rot,
    },
    OpcodeInfo {
        value: OP_SWAP,
        name: "OP_SWAP",
        length: 1,
        func: opcode_swap,
    },
    OpcodeInfo {
        value: OP_TUCK,
        name: "OP_TUCK",
        length: 1,
        func: opcode_tuck,
    },
    OpcodeInfo {
        value: OP_CAT,
        name: "OP_CAT",
        length: 1,
        func: opcode_cat,
    },
    OpcodeInfo {
        value: OP_SUBSTR,
        name: "OP_SUBSTR",
        length: 1,
        func: opcode_substr,
    },
    OpcodeInfo {
        value: OP_LEFT,
        name: "OP_LEFT",
        length: 1,
        func: opcode_left,
    },
    OpcodeInfo {
        value: OP_RIGHT,
        name: "OP_RIGHT",
        length: 1,
        func: opcode_right,
    },
    OpcodeInfo {
        value: OP_SIZE,
        name: "OP_SIZE",
        length: 1,
        func: opcode_size,
    },
    OpcodeInfo {
        value: OP_INVERT,
        name: "OP_INVERT",
        length: 1,
        func: opcode_invert,
    },
    OpcodeInfo {
        value: OP_AND,
        name: "OP_AND",
        length: 1,
        func: opcode_and,
    },
    OpcodeInfo {
        value: OP_OR,
        name: "OP_OR",
        length: 1,
        func: opcode_or,
    },
    OpcodeInfo {
        value: OP_XOR,
        name: "OP_XOR",
        length: 1,
        func: opcode_xor,
    },
    OpcodeInfo {
        value: OP_EQUAL,
        name: "OP_EQUAL",
        length: 1,
        func: opcode_equal,
    },
    OpcodeInfo {
        value: OP_EQUALVERIFY,
        name: "OP_EQUALVERIFY",
        length: 1,
        func: opcode_equal_verify,
    },
    OpcodeInfo {
        value: OP_ROTR,
        name: "OP_ROTR",
        length: 1,
        func: opcode_rotr,
    },
    OpcodeInfo {
        value: OP_ROTL,
        name: "OP_ROTL",
        length: 1,
        func: opcode_rotl,
    },
    OpcodeInfo {
        value: OP_1ADD,
        name: "OP_1ADD",
        length: 1,
        func: opcode_1add,
    },
    OpcodeInfo {
        value: OP_1SUB,
        name: "OP_1SUB",
        length: 1,
        func: opcode_1sub,
    },
    OpcodeInfo {
        value: OP_2MUL,
        name: "OP_2MUL",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_2DIV,
        name: "OP_2DIV",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_NEGATE,
        name: "OP_NEGATE",
        length: 1,
        func: opcode_negate,
    },
    OpcodeInfo {
        value: OP_ABS,
        name: "OP_ABS",
        length: 1,
        func: opcode_abs,
    },
    OpcodeInfo {
        value: OP_NOT,
        name: "OP_NOT",
        length: 1,
        func: opcode_not,
    },
    OpcodeInfo {
        value: OP_0NOTEQUAL,
        name: "OP_0NOTEQUAL",
        length: 1,
        func: opcode_0notequal,
    },
    OpcodeInfo {
        value: OP_ADD,
        name: "OP_ADD",
        length: 1,
        func: opcode_add,
    },
    OpcodeInfo {
        value: OP_SUB,
        name: "OP_SUB",
        length: 1,
        func: opcode_sub,
    },
    OpcodeInfo {
        value: OP_MUL,
        name: "OP_MUL",
        length: 1,
        func: opcode_mul,
    },
    OpcodeInfo {
        value: OP_DIV,
        name: "OP_DIV",
        length: 1,
        func: opcode_div,
    },
    OpcodeInfo {
        value: OP_MOD,
        name: "OP_MOD",
        length: 1,
        func: opcode_mod,
    },
    OpcodeInfo {
        value: OP_LSHIFT,
        name: "OP_LSHIFT",
        length: 1,
        func: opcode_lshift,
    },
    OpcodeInfo {
        value: OP_RSHIFT,
        name: "OP_RSHIFT",
        length: 1,
        func: opcode_rshift,
    },
    OpcodeInfo {
        value: OP_BOOLAND,
        name: "OP_BOOLAND",
        length: 1,
        func: opcode_bool_and,
    },
    OpcodeInfo {
        value: OP_BOOLOR,
        name: "OP_BOOLOR",
        length: 1,
        func: opcode_bool_or,
    },
    OpcodeInfo {
        value: OP_NUMEQUAL,
        name: "OP_NUMEQUAL",
        length: 1,
        func: opcode_num_equal,
    },
    OpcodeInfo {
        value: OP_NUMEQUALVERIFY,
        name: "OP_NUMEQUALVERIFY",
        length: 1,
        func: opcode_num_equal_verify,
    },
    OpcodeInfo {
        value: OP_NUMNOTEQUAL,
        name: "OP_NUMNOTEQUAL",
        length: 1,
        func: opcode_num_not_equal,
    },
    OpcodeInfo {
        value: OP_LESSTHAN,
        name: "OP_LESSTHAN",
        length: 1,
        func: opcode_less_than,
    },
    OpcodeInfo {
        value: OP_GREATERTHAN,
        name: "OP_GREATERTHAN",
        length: 1,
        func: opcode_greater_than,
    },
    OpcodeInfo {
        value: OP_LESSTHANOREQUAL,
        name: "OP_LESSTHANOREQUAL",
        length: 1,
        func: opcode_less_than_or_equal,
    },
    OpcodeInfo {
        value: OP_GREATERTHANOREQUAL,
        name: "OP_GREATERTHANOREQUAL",
        length: 1,
        func: opcode_greater_than_or_equal,
    },
    OpcodeInfo {
        value: OP_MIN,
        name: "OP_MIN",
        length: 1,
        func: opcode_min,
    },
    OpcodeInfo {
        value: OP_MAX,
        name: "OP_MAX",
        length: 1,
        func: opcode_max,
    },
    OpcodeInfo {
        value: OP_WITHIN,
        name: "OP_WITHIN",
        length: 1,
        func: opcode_within,
    },
    OpcodeInfo {
        value: OP_RIPEMD160,
        name: "OP_RIPEMD160",
        length: 1,
        func: opcode_ripemd160,
    },
    OpcodeInfo {
        value: OP_SHA1,
        name: "OP_SHA1",
        length: 1,
        func: opcode_sha1,
    },
    OpcodeInfo {
        value: OP_BLAKE256,
        name: "OP_BLAKE256",
        length: 1,
        func: opcode_blake256,
    },
    OpcodeInfo {
        value: OP_HASH160,
        name: "OP_HASH160",
        length: 1,
        func: opcode_hash160,
    },
    OpcodeInfo {
        value: OP_HASH256,
        name: "OP_HASH256",
        length: 1,
        func: opcode_hash256,
    },
    OpcodeInfo {
        value: OP_CODESEPARATOR,
        name: "OP_CODESEPARATOR",
        length: 1,
        func: opcode_disabled,
    },
    OpcodeInfo {
        value: OP_CHECKSIG,
        name: "OP_CHECKSIG",
        length: 1,
        func: opcode_check_sig,
    },
    OpcodeInfo {
        value: OP_CHECKSIGVERIFY,
        name: "OP_CHECKSIGVERIFY",
        length: 1,
        func: opcode_check_sig_verify,
    },
    OpcodeInfo {
        value: OP_CHECKMULTISIG,
        name: "OP_CHECKMULTISIG",
        length: 1,
        func: opcode_check_multi_sig,
    },
    OpcodeInfo {
        value: OP_CHECKMULTISIGVERIFY,
        name: "OP_CHECKMULTISIGVERIFY",
        length: 1,
        func: opcode_check_multi_sig_verify,
    },
    OpcodeInfo {
        value: OP_NOP1,
        name: "OP_NOP1",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_CHECKLOCKTIMEVERIFY,
        name: "OP_CHECKLOCKTIMEVERIFY",
        length: 1,
        func: opcode_check_lock_time_verify,
    },
    OpcodeInfo {
        value: OP_CHECKSEQUENCEVERIFY,
        name: "OP_CHECKSEQUENCEVERIFY",
        length: 1,
        func: opcode_check_sequence_verify,
    },
    OpcodeInfo {
        value: OP_NOP4,
        name: "OP_NOP4",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_NOP5,
        name: "OP_NOP5",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_NOP6,
        name: "OP_NOP6",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_NOP7,
        name: "OP_NOP7",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_NOP8,
        name: "OP_NOP8",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_NOP9,
        name: "OP_NOP9",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_NOP10,
        name: "OP_NOP10",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_SSTX,
        name: "OP_SSTX",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_SSGEN,
        name: "OP_SSGEN",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_SSRTX,
        name: "OP_SSRTX",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_SSTXCHANGE,
        name: "OP_SSTXCHANGE",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_CHECKSIGALT,
        name: "OP_CHECKSIGALT",
        length: 1,
        func: opcode_check_sig_alt,
    },
    OpcodeInfo {
        value: OP_CHECKSIGALTVERIFY,
        name: "OP_CHECKSIGALTVERIFY",
        length: 1,
        func: opcode_check_sig_alt_verify,
    },
    OpcodeInfo {
        value: OP_SHA256,
        name: "OP_SHA256",
        length: 1,
        func: opcode_sha256,
    },
    OpcodeInfo {
        value: OP_TADD,
        name: "OP_TADD",
        length: 1,
        func: opcode_tadd,
    },
    OpcodeInfo {
        value: OP_TSPEND,
        name: "OP_TSPEND",
        length: 1,
        func: opcode_tspend,
    },
    OpcodeInfo {
        value: OP_TGEN,
        name: "OP_TGEN",
        length: 1,
        func: opcode_tgen,
    },
    OpcodeInfo {
        value: OP_UNKNOWN196,
        name: "OP_UNKNOWN196",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN197,
        name: "OP_UNKNOWN197",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN198,
        name: "OP_UNKNOWN198",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN199,
        name: "OP_UNKNOWN199",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN200,
        name: "OP_UNKNOWN200",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN201,
        name: "OP_UNKNOWN201",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN202,
        name: "OP_UNKNOWN202",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN203,
        name: "OP_UNKNOWN203",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN204,
        name: "OP_UNKNOWN204",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN205,
        name: "OP_UNKNOWN205",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN206,
        name: "OP_UNKNOWN206",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN207,
        name: "OP_UNKNOWN207",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN208,
        name: "OP_UNKNOWN208",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN209,
        name: "OP_UNKNOWN209",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN210,
        name: "OP_UNKNOWN210",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN211,
        name: "OP_UNKNOWN211",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN212,
        name: "OP_UNKNOWN212",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN213,
        name: "OP_UNKNOWN213",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN214,
        name: "OP_UNKNOWN214",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN215,
        name: "OP_UNKNOWN215",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN216,
        name: "OP_UNKNOWN216",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN217,
        name: "OP_UNKNOWN217",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN218,
        name: "OP_UNKNOWN218",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN219,
        name: "OP_UNKNOWN219",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN220,
        name: "OP_UNKNOWN220",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN221,
        name: "OP_UNKNOWN221",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN222,
        name: "OP_UNKNOWN222",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN223,
        name: "OP_UNKNOWN223",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN224,
        name: "OP_UNKNOWN224",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN225,
        name: "OP_UNKNOWN225",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN226,
        name: "OP_UNKNOWN226",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN227,
        name: "OP_UNKNOWN227",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN228,
        name: "OP_UNKNOWN228",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN229,
        name: "OP_UNKNOWN229",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN230,
        name: "OP_UNKNOWN230",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN231,
        name: "OP_UNKNOWN231",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN232,
        name: "OP_UNKNOWN232",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN233,
        name: "OP_UNKNOWN233",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN234,
        name: "OP_UNKNOWN234",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN235,
        name: "OP_UNKNOWN235",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN236,
        name: "OP_UNKNOWN236",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN237,
        name: "OP_UNKNOWN237",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN238,
        name: "OP_UNKNOWN238",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN239,
        name: "OP_UNKNOWN239",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN240,
        name: "OP_UNKNOWN240",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN241,
        name: "OP_UNKNOWN241",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN242,
        name: "OP_UNKNOWN242",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN243,
        name: "OP_UNKNOWN243",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN244,
        name: "OP_UNKNOWN244",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN245,
        name: "OP_UNKNOWN245",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN246,
        name: "OP_UNKNOWN246",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN247,
        name: "OP_UNKNOWN247",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_UNKNOWN248,
        name: "OP_UNKNOWN248",
        length: 1,
        func: opcode_nop,
    },
    OpcodeInfo {
        value: OP_INVALID249,
        name: "OP_INVALID249",
        length: 1,
        func: opcode_invalid,
    },
    OpcodeInfo {
        value: OP_SMALLINTEGER,
        name: "OP_SMALLINTEGER",
        length: 1,
        func: opcode_invalid,
    },
    OpcodeInfo {
        value: OP_PUBKEYS,
        name: "OP_PUBKEYS",
        length: 1,
        func: opcode_invalid,
    },
    OpcodeInfo {
        value: OP_UNKNOWN252,
        name: "OP_UNKNOWN252",
        length: 1,
        func: opcode_invalid,
    },
    OpcodeInfo {
        value: OP_PUBKEYHASH,
        name: "OP_PUBKEYHASH",
        length: 1,
        func: opcode_invalid,
    },
    OpcodeInfo {
        value: OP_PUBKEY,
        name: "OP_PUBKEY",
        length: 1,
        func: opcode_invalid,
    },
    OpcodeInfo {
        value: OP_INVALIDOPCODE,
        name: "OP_INVALIDOPCODE",
        length: 1,
        func: opcode_invalid,
    },
];
