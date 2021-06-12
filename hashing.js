/**
 * Hashing module 
 * 
 */

const crypto = require("crypto");
const bcrypt = require("bcrypt");

/* Hashing with random salt */

// ============================================================

// Crypto hash ( built in node )
const hash = async (str) => {
    return new Promise((resolve, reject) => {
        try {
            const algorithm = "sha256"; // should be at env
            const hash = crypto.createHash(algorithm).update(str).digest("hex");
            resolve(hash);
        } catch (err) {
            console.error(err);
            reject(err);
        }
    });
};

const verifyHash = async (str, hashedStr) => {
    return new Promise(async (resolve, reject) => {
        try {
            const newHashed = await hash(str);
            resolve(newHashed === hashedStr);
        } catch (err) {
            console.error(err);
            reject(err);
        }
    });
};

// ============================================================

// bcrypt hash
const bcryptHash = async (str) => {
    const salt = await bcrypt.genSalt();
    const hash = await bcrypt.hash(str, salt);
    return hash;
};

const bcryptVerifyHash = async (str, hash) => {
    return new Promise((resolve, reject) => {
        bcrypt.compare(str, hash, (err, same) => {
            if (err) {
                return reject(err);
            }
            return resolve(same);
        });
    });
};
// ============================================================
module.exports = {
    hash,
    verifyHash,
    bcryptHash,
    bcryptVerifyHash,
};
