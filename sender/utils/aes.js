const crypto = require('crypto');

const aes256gcm = (key) => {
    const ALGO = 'aes-256-gcm';

    const encrypt = (str) => {
        const iv = Buffer.from(crypto.randomBytes(12), 'utf8');
        const cipher = crypto.createCipheriv(ALGO, key, iv);
        let enc = cipher.update(str, 'utf8', 'base64');
        enc += cipher.final('base64');
        return [enc, iv, cipher.getAuthTag()];
    };

    const decrypt = (enc, iv, authTag) => {
        const decipher = crypto.createDecipheriv(ALGO, key, iv);
        decipher.setAuthTag(authTag);
        let str = decipher.update(enc, 'base64', 'utf8');
        str += decipher.final('utf8');
        return str;
    };

    return {
        encrypt,
        decrypt,
    };
};

module.exports = aes256gcm;