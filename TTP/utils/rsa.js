const bcu = require('bigint-crypto-utils');
const bic = require('bigint-conversion');
const config = require('../config/config');

// https://prnt.sc/11h3927
class RSAPrivateKey {

    constructor(d, n) {
        this.d = bic.bigintToHex(d);
        this.n = bic.bigintToHex(n);
    }

    decrypt(data, inputType, outputType) {
        const bigint = toBigInt(data, inputType);
        const decrypted = bcu.modPow(bigint, bic.hexToBigint(this.d), bic.hexToBigint(this.n));
        return transfromBigInt(decrypted, outputType);
    }

    sign(data, inputType, outputType) {
        const bigint = toBigInt(data, inputType);
        const decrypted = bcu.modPow(bigint, bic.hexToBigint(this.d), bic.hexToBigint(this.n));
        return transfromBigInt(decrypted, outputType);
    }

}

class RSAPublicKey {

    constructor(e, n) {
        this.e = bic.bigintToHex(e);
        this.n = bic.bigintToHex(n);
    }

    encrypt(data, inputType, outputType) {
        const bigint = toBigInt(data, inputType);
        const encrypted = bcu.modPow(bigint, bic.hexToBigint(this.e), bic.hexToBigint(this.n));
        return transfromBigInt(encrypted, outputType);
    }

    verify(data, inputType, outputType) {
        const bigint = toBigInt(data, inputType);
        const encrypted = bcu.modPow(bigint, bic.hexToBigint(this.e), bic.hexToBigint(this.n));
        return transfromBigInt(encrypted, outputType);
    }
    
    toJSON() {
        return {
            e: this.e,
            n: this.n
        }
    }

    fromJSON(json) {
        this.e = json.e;
        this.n = json.n;
    }

}

function transfromBigInt(bigint, type) {
    switch(type.toLowerCase()) {
        case 'bigint':
            return bigint;
        case 'hex':
            return bic.bigintToHex(bigint);
        case 'text':
            return bic.bigintToText(bigint);
        case 'buffer':
            return bic.bigintToBuf(bigint);
        default:
            return null;
    }
}

function toBigInt(data, type) {
    switch(type.toLowerCase()) {
        case 'bigint':
            return data;
        case 'hex':
            return bic.hexToBigint(data);
        case 'text':
            return bic.textToBigint(data);
        case 'buffer':
            return bic.bufToBigint(data);
        default:
            return null;
    }
}

async function generateKeys(bitLength) {

    // https://prnt.sc/11h43ht
    const e = 65537n;
    let p;
    let q;
    let n;
    let phi;

    do {
        p = await bcu.prime(bitLength / 2 + 1);
        q = await bcu.prime(bitLength / 2);
        n = p * q;
        phi = (p - 1n) * (q - 1n);
    } while (bcu.bitLength(n) !== bitLength || phi % e === 0n);

    // https://prnt.sc/11h57lb
    const d = bcu.modInv(e, phi);
    const publicKey = new RSAPublicKey(e, n);
    const privateKey = new RSAPrivateKey(d, n);

    return {
        publicKey,
        privateKey
    };

}

async function generateBlindFactor(n) {

    let blindFactor;
    let randomBuffer;

    do {
        randomBuffer = await bcu.randBytes(16);
        blindFactor = bic.bufToBigint(randomBuffer);
    } while (blindFactor % n === 0n)

    return blindFactor;

}

async function blindMethod(data, blindFactor, receiverPublicKey, inputType, outputType) {
    const bigint = toBigInt(data, inputType);
    const encryptedBf = receiverPublicKey.encrypt(blindFactor, 'bigint', 'bigint');
    const blinded = bcu.toZn(bigint * encryptedBf, bic.hexToBigint(receiverPublicKey.n));
    return transfromBigInt(blinded, outputType);
}

async function unblindMethod(data, blindFactor, receiverPublicKey, inputType, outputType) {
    const bigint = toBigInt(data, inputType);
    const invBf = bcu.modInv(blindFactor, bic.hexToBigint(receiverPublicKey.n));
    const unblinded = bcu.toZn(bigint * invBf, bic.hexToBigint(receiverPublicKey.n));
    return transfromBigInt(unblinded, outputType);
}

class RSAManager {

    blindFactors = [];
    ready = false;

    constructor() {
        const useDefaults = config.rsa.use_defaults;
        if(useDefaults) {
            this.loadKeys();
        } else {
            this.generateKeys();
        }
    }

    async generateKeys() {
        const strength = config.rsa.strength;
        this.rsaKeyPair = await generateKeys(strength);
        this.ready = true;
        console.log("[!] Clave RSA generada.");
    }

    loadKeys() {
        const publicKeyConf = config.rsa.defaults.public_key;
        const privateKeyConf = config.rsa.defaults.private_key;

        const publicKey = new RSAPublicKey(publicKeyConf.e, publicKeyConf.n);
        const privateKey = new RSAPrivateKey(privateKeyConf.d, privateKeyConf.n);

        this.rsaKeyPair = {
            publicKey,
            privateKey
        };

        this.ready = true;
        console.log("[!] Clave RSA generada.");
    }

    async blind(data, reciverPublicKey, inputType, outputType) {
        const blindFactor = await this.getBlindFactor(reciverPublicKey);
        const blinded = blindMethod(data, blindFactor, reciverPublicKey, inputType, outputType);
        return blinded;
    }

    async unblind(data, reciverPublicKey, inputType, outputType) {
        const blindFactor = await this.getBlindFactor(reciverPublicKey);
        const unblinded = unblindMethod(data, blindFactor, reciverPublicKey, inputType, outputType);
        return unblinded;
    }

    async getBlindFactor(reciverPublicKey) {
        let bfQuery = this.blindFactors.filter(x => x.n === reciverPublicKey.n);
        if(bfQuery.length === 1) {
            return bic.hexToBigint(bfQuery[0].value);
        }

        let blindFactor = await generateBlindFactor(bic.hexToBigint(reciverPublicKey.n));
        this.blindFactors.push({
            n: reciverPublicKey.n,
            value: bic.bigintToHex(blindFactor)
        })

        return blindFactor;
    }

    getRSAKeyPair() {
        return this.rsaKeyPair;
    }

    getPublicKey() {
        return this.rsaKeyPair.publicKey;
    }

    getPrivateKey() {
        return this.rsaKeyPair.privateKey;
    }

    encrypt(data, inputType, outputType) {
        return this.rsaKeyPair.publicKey.encrypt(data, inputType, outputType);
    }

    verify(data, inputType, outputType) {
        return this.rsaKeyPair.publicKey.verify(data, inputType, outputType);
    }

    decrypt(data, inputType, outputType) {
        return this.rsaKeyPair.privateKey.decrypt(data, inputType, outputType);
    }

    sign(data, inputType, outputType) {
        return this.rsaKeyPair.privateKey.sign(data, inputType, outputType);
    }

}

module.exports = {
    RSAPrivateKey,
    RSAPublicKey,
    RSAManager,
    generateKeys
}