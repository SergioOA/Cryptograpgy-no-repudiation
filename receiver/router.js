const router = require('express').Router();
const chalk = require('chalk');
const axios = require('axios');
const aes256gcm = require('./utils/aes');
const bic = require('bigint-conversion');
const {RSAManager,RSAPublicKey} = require('./utils/rsa');

const rsaManager = new RSAManager();

let encryptedMessage = "";
let authTag = "";
let aesSeed = "";

router.post('/webhook', async (req, res) => {
	
	// Data inside the body of the POST HTTP request
	const receivedData = req.body;
	console.log(chalk.green("Recibido un mensaje:", JSON.stringify(receivedData)));

	// We get the public key so we can verify the signed message
	const publicKey = new RSAPublicKey(0n, 0n);
	publicKey.fromJSON(receivedData.publicKey);

	// We verify the message and get the data
	try {
		const verified = publicKey.verify(receivedData.signed, "hex", "text");
		const verifiedJSON = JSON.parse(verified);
		encryptedMessage = verifiedJSON.encrypted;
		authTag = bic.hexToBuf(verifiedJSON.authTag);
		aesSeed = bic.hexToBuf(verifiedJSON.aesSeed);

		console.log(chalk.blueBright("Se ha verificado la signature correctamente."));

		// We reply the data we got so he knows we recived it. We also sign it
		// so there is no doubt it's us.
		res.send({
			signed: rsaManager.sign(JSON.stringify(verifiedJSON), "text", "hex"),
			publicKey: rsaManager.getPublicKey().toJSON(),
		});

		// We wait 1 second to give time to the sender to give the key to the TTP.
		setTimeout(async () => {

			// We ask the TTP for the key, it has been encrypted using our public key, so we
			// must decrypt it before using it.
			const keyData = await axios.get("http://localhost:3021/getKey");
			const key = rsaManager.decrypt(keyData.data.key, "hex", "text");
			const keyBuffer = bic.hexToBuf(key);
			console.log(chalk.magenta("Se ha recibido una respuesta de la TTP!", key));

			// Now we can finally decrypt the original message using the key we got from the TTP.
			const aesCipher = aes256gcm(aesSeed);
			const decriptedMsg = aesCipher.decrypt(encryptedMessage, keyBuffer, authTag);

			// Yayyyyy! Finally decrypted!
			console.log(decriptedMsg)

		}, 1000);

	} 
	
	// If the JSON parse fails, it means the public key was not correct.
	catch(e) {
		console.log(e)
		res.json({
			status: "error"
		});
	}

});

module.exports = router;