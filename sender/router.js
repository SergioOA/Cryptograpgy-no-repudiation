const router = require('express').Router();
const chalk = require('chalk');
const axios = require('axios');
const bic = require('bigint-conversion');
const {RSAManager,RSAPublicKey} = require('./utils/rsa');
const aes256gcm = require('./utils/aes');
const crypto = require('crypto');
const rsaManager = new RSAManager();

/**
 * TODO: Agregar timestamp, origin, destinations
 */

router.get('/send', async (req, res) => {

	// Message we want to send
	const msg = 'Este es un mensaje con no-repudio!';

	// We are gonna send the message encrypted using aes-256-gcm but
	// we are not gonna send him the seed so he won't be able to decrypt
	// the message. He will need to message the TTP to get it.
	const aesSeed = Buffer.from(crypto.randomBytes(32), 'utf8');
	const aesCipher = aes256gcm(aesSeed);
	const [encrypted, iv, authTag] = aesCipher.encrypt(msg);
	const encryptionData = JSON.stringify({
		encrypted,
		authTag: bic.bufToHex(authTag),
		iv: bic.bufToHex(iv)
	});

	// We must sign the data so the reciver knows it's us.
	const signed = rsaManager.sign(encryptionData, "text", "hex");
	console.log(chalk.green("Enviando mensaje firmado:", signed))

	// Sending the message to the server, if he recives the message we will
	// recive an ACK.
	const reply = await axios.post("http://localhost:3022/webhook", {
		signed,
		publicKey: rsaManager.getPublicKey().toJSON()
	});

	// The reply is signed by the receiver, so we must verify the signature.
	const receivedData = reply.data;
	const publicKey = new RSAPublicKey(0n, 0n);
	publicKey.fromJSON(receivedData.publicKey);
	console.log(chalk.magenta("Se ha recibido una respuesta!", JSON.stringify(receivedData)));

	// We verify the message and check if the data is the same we sent him
	try {
		const verified = publicKey.verify(receivedData.signed, "hex", "text");
		const verifiedJSON = JSON.parse(verified);
		console.log(chalk.blueBright("Se ha verificado la signature correctamente."));

		// If it's not the same, there is an error with the communication and we
		// must stop it here.
		if(verifiedJSON.encrypted !== encrypted) {
			res.json({
				status: "error",
				reason: "data does not match"
			});
			return;
		}

		console.log(chalk.cyanBright("La información recibida se corresponde con la enviada."));

		// We know the receiver received the message correctly, so we
		// can send the aes seed to decrypt the message to the TTP.
		const signedKey = publicKey.encrypt(bic.bufToHex(aesSeed), "text", "hex");
		console.log(chalk.green("Enviando mensaje a la TTP:", signedKey))
		const ttpConfirmation = await axios.post("http://localhost:3021/webhook", {
			aesSeed: signedKey
		});

		console.log(chalk.magenta("Se ha recibido una respuesta de la TTP!", JSON.stringify(ttpConfirmation.data)));

	} 
	
	// If the JSON parse fails, it means the public key was not correct.
	catch(e) {
		res.json({
			status: "error",
			reason: "receiver didn't provide a valid ACK"
		});
	}

});

module.exports = router;