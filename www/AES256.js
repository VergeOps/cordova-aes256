var exec = require('cordova/exec');

var AES256 = function () {};

AES256.prototype.encrypt = function (value, success, error) {
    if (value) {
        exec(success, error, 'AES256', 'encrypt', [value]);
    } else {
        success('');
    }
};

AES256.prototype.decrypt = function (value, success, error) {
    if (value) {
        exec(success, error, 'AES256', 'decrypt', [value]);
    } else {
        success('');
    }
};

AES256.prototype.generateCipher = function (devicePublicKey, deviceRandom, success, error) {
    if (devicePublicKey && deviceRandom) {
        exec(success, error, 'AES256', 'generateCipher', [devicePublicKey, deviceRandom]);
    } else {
        success('');
    }
};

AES256.prototype.generateKeyPair = function (success, error) {
    exec(success, error, 'AES256', 'generateKeyPair', []);
};


var aES256 = new AES256();

module.exports = aES256;