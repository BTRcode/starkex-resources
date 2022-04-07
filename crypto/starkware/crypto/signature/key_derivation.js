/////////////////////////////////////////////////////////////////////////////////
// Copyright 2019 StarkWare Industries Ltd.                                    //
//                                                                             //
// Licensed under the Apache License, Version 2.0 (the "License").             //
// You may not use this file except in compliance with the License.            //
// You may obtain a copy of the License at                                     //
//                                                                             //
// https://www.starkware.co/open-source-license/                               //
//                                                                             //
// Unless required by applicable law or agreed to in writing,                  //
// software distributed under the License is distributed on an "AS IS" BASIS,  //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    //
// See the License for the specific language governing permissions             //
// and limitations under the License.                                          //
/////////////////////////////////////////////////////////////////////////////////
// const privateKey = testData.meta_data.transfer_order.private_key.substring(2);
// console.log(privateKey)

let ethers = require('ethers')
var Web3 = require('web3');
const { hdkey } = require('ethereumjs-wallet');
const assert = require('assert');
const bip39 = require('bip39');
const encUtils = require('enc-utils');
const BN = require('bn.js');
const hash = require('hash.js');
const { ec } = require('./signature.js');
const layer = 'starkex';
const application = 'starkdeployement';
const starkwareCrypto = require('./signature.js');
const testData = require('./signature_test_data.json');
let provider = ethers.getDefaultProvider('ropsten')

const mnemonic = 'range mountain blast problem vibrant void vivid doctor cluster enough melody ' +
     'salt layer language laptop boat major space monkey unit glimpse pause change vibrant';
const ethAddress = '0xe9105bB8a2444007D80A5f032181Cb2a8db96B4d';

/*
 Returns an integer from a given section of bits out of a hex string.
 hex is the target hex string to slice.
 start represents the index of the first bit to cut from the hex string (binary) in LSB order.
 end represents the index of the last bit to cut from the hex string.
*/

function getIntFromBits(hex, start, end = undefined) {
    const bin = encUtils.hexToBinary(hex);
    const bits = bin.slice(start, end);
    const int = encUtils.binaryToNumber(bits);
    return int;
}

/*
 Derives key-pair from given mnemonic string and path.
 mnemonic should be a sentence comprised of 12 words with single spaces between them.
 path is a formatted string describing the stark key path based on the layer, application and eth
 address.
*/

function getKeyPairFromPath(mnemonic, path) {
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const keySeed = hdkey
        .fromMasterSeed(seed, 'hex')
        .derivePath(path)
        .getWallet()
        .getPrivateKeyString();
    const starkEcOrder = ec.n;
    const grinded = grindKey(keySeed, starkEcOrder)
    console.log(grinded)
    return ec.keyFromPrivate(grinded, 'hex');
}

/*
 Calculates the stark path based on the layer, application, eth address and a given index.
 layer is a string representing the operating layer (usually 'starkex'). //layer= starkex//
 application is a string representing the relevant application (For a list of valid applications,
 refer to https://starkware.co/starkex/docs/requirementsApplicationParameters.html).
 ethereumAddress is a string representing the ethereum public key from which we derive the stark
 key.
 index represents an index of the possible associated wallets derived from the seed.
*/

function getAccountPath(layer, application, ethereumAddress, index) {
    const layerHash = hash
        .sha256()
        .update(layer)
        .digest('hex');
    const applicationHash = hash
        .sha256()
        .update(application)
        .digest('hex');
    const layerInt = getIntFromBits(layerHash, -31);
    const applicationInt = getIntFromBits(applicationHash, -31);
    // Draws the 31 LSBs of the eth address.
    const ethAddressInt1 = getIntFromBits(ethereumAddress, -31);
    // Draws the following 31 LSBs of the eth address.
    const ethAddressInt2 = getIntFromBits(ethereumAddress, -62, -31);
    return `m/2645'/${layerInt}'/${applicationInt}'/${ethAddressInt1}'/${ethAddressInt2}'/${index}`;
}

/*
 This function receives a key seed and produces an appropriate StarkEx key from a uniform
 distribution.
 Although it is possible to define a StarkEx key as a residue between the StarkEx EC order and a
 random 256bit digest value, the result would be a biased key. In order to prevent this bias, we
 deterministically search (by applying more hashes, AKA grinding) for a value lower than the largest
 256bit multiple of StarkEx EC order.
*/

function grindKey(keySeed, keyValLimit) {
    const sha256EcMaxDigest = new BN(
        '1 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000',
        16
    );
    const maxAllowedVal = sha256EcMaxDigest.sub(sha256EcMaxDigest.mod(keyValLimit));
    let i = 0;
    let key = hashKeyWithIndex(keySeed, i);
    i++;
    // Make sure the produced key is devided by the Stark EC order, and falls within the range
    // [0, maxAllowedVal).
    while (!(key.lt(maxAllowedVal))) {
        key = hashKeyWithIndex(keySeed.toString('hex'), i);
        i++;
    }
    return key.umod(keyValLimit).toString('hex');
}

function hashKeyWithIndex(key, index) {
    return new BN(
        hash
            .sha256()
            .update(
                encUtils.hexToBuffer(
                    encUtils.removeHexPrefix(key) +
                    encUtils.sanitizeBytes(encUtils.numberToHex(index), 2)
                )
            )
            .digest('hex'),
        16
    );
}

module.exports = {
    StarkExEc: ec.n,  // Data.
    getKeyPairFromPath, getAccountPath, grindKey  // Function.
};

const path = getAccountPath(layer, application, ethAddress, 10)
console.log(typeof path)
console.log(path)
let data = getKeyPairFromPath(mnemonic, path);
const publicKey = starkwareCrypto.ec.keyFromPublic(data.getPublic(true, 'hex'), 'hex');
const pkey=data.getPrivate('hex');                 //grindkey is nothing but privatekey//
console.log(pkey);
const publicKeyX = publicKey.pub.getX();
console.log(publicKeyX.toString(16))               //This is the publickey or starkkey//

assert(
    publicKeyX.toString(16) === testData.settlement.party_a_order.public_key.substring(2),
    `Got: ${publicKeyX.toString(16)}.
    Expected: ${testData.settlement.party_a_order.public_key.substring(2)}`
);

const { party_a_order: partyAOrder } = testData.settlement;
const msgHash = starkwareCrypto.getLimitOrderMsgHash(
    partyAOrder.vault_id_sell, // - vault_sell (uint31)
    partyAOrder.vault_id_buy, // - vault_buy (uint31)
    partyAOrder.amount_sell, // - amount_sell (uint63 decimal str)
    partyAOrder.amount_buy, // - amount_buy (uint63 decimal str)
    partyAOrder.token_sell, // - token_sell (hex str with 0x prefix < prime)
    partyAOrder.token_buy, // - token_buy (hex str with 0x prefix < prime)
    partyAOrder.nonce, // - nonce (uint31)
    partyAOrder.expiration_timestamp // - expiration_timestamp (uint22)
);

assert(msgHash === testData.meta_data.party_a_order.message_hash.substring(2),
    `Got: ${msgHash}. Expected: ` + testData.meta_data.party_a_order.message_hash.substring(2));

const msgSignature = starkwareCrypto.sign(data, msgHash);
console.log("starkSignature : ", msgSignature);
const { r, s } = msgSignature;
console.log(r.toString(16),s.toString(16))          //signature : r and s values //

//verification of the sign//
assert(starkwareCrypto.verify(publicKey, msgHash, msgSignature));
assert(r.toString(16) === partyAOrder.signature.r.substring(2),
    `Got: ${r.toString(16)}. Expected: ${partyAOrder.signature.r.substring(2)}`);
assert(s.toString(16) === partyAOrder.signature.s.substring(2),
    `Got: ${s.toString(16)}. Expected: ${partyAOrder.signature.s.substring(2)}`);

// use the metamask wallet (nonBIP32 key generation) //
async function genarateKeyNonBIP32(){
console.log('nonBIP32 key generation');
const privateKey = '3f5df68aaabce6c1ecb23fc6977b3c9f06a3aad17e2c2ecc8abdeea8a193b30d';
let wallet = new ethers.Wallet(privateKey)
let message = "hello world"
let flatsig = await wallet.signMessage(message);
let sig = ethers.utils.splitSignature(flatsig);
const grinded = grindKey(sig.r, ec.n)
console.log("grind Key :",grinded)
let datas = ec.keyFromPrivate(grinded, 'hex');
const publicKey1 = starkwareCrypto.ec.keyFromPublic(datas.getPublic(true, 'hex'), 'hex');
const pkey1=datas.getPrivate('hex');                               //grindkey is nothing but privatekey//
console.log("private Key :",pkey1);
const publicKey1X = publicKey1.pub.getX(); 
console.log("public Key :",publicKey1X.toString(16))               //This is the publickey or starkkey//
}
genarateKeyNonBIP32();

