var express = require('express');
const db = require('../database/db_connect');
var router = express.Router();
const jwt = require('../modules/jwt');
const shell = require('shelljs');
//const Client = require('ssh2-sftp-client');
const path = require("path");

const {FileSystemWallet, Gateway, X509WalletMixin} = require('fabric-network');
const fs = require("fs");
const ccpPath = path.resolve('./config/connection-org1.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);

const cors = require('cors');
const FabricCAServices = require("fabric-ca-client");
const axios = require('axios');
const crypto = require('crypto');

router.use(cors({}));



//로그아웃은 프론트에서 토큰 삭제로 조치
// router.get('/auth/ca/admin/logout', async function(req, res, next) {
//
//   let token = req.headers.token;
//
//   console.log(token);
//
//   res.status(401).json({
//     "result" : true,
//   });
//
// });

module.exports = router;
