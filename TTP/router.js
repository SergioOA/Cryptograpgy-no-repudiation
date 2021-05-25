const router = require('express').Router();
const chalk = require('chalk');
const {RSAManager} = require('./utils/rsa');

const rsaManager = new RSAManager();
let aesSeed = "";

router.post('/webhook', async (req, res) => {
	
	// Data inside the body of the POST HTTP request
	const receivedData = req.body;
	console.log(chalk.green("Recibido un mensaje:", JSON.stringify(receivedData)));

	// Let's save the data, we should keep track of multiple keys at the same time,
	// probably make the sender give a UUID we can use as an index to his data.
	// Since this is an example, we are only gonna save one key at the same time.
	aesSeed = receivedData.aesSeed;

	// We reply with the data signed by the TTP, so he has proof he sent us the
	// key.
	const signed = rsaManager.sign(JSON.stringify(receivedData), "text", "hex");
	console.log(chalk.yellowBright("Respondiendo:", JSON.stringify(signed)));

	res.json({
		status: "ok",
		signed
	})

});


router.get('/getKey', async (req, res) => {
	res.json({aesSeed});
});

module.exports = router;