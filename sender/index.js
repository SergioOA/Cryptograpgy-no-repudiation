const express = require('express');
const app = express();

/* Temporal: Permitimos CORS desde todas partes */
const cors = require('cors');
app.use(cors({credentials: true, origin: true}));

/* Agregamos el json de los post en req.body */
app.use(express.json());

/* API */
const router = require('./router');
app.use('/', router);

/* Empezamos a escuchar en el puerto configurado */
app.listen(3020, () => {
	console.log("[!] Servidor iniciado");
});