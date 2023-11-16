var express = require('express');
const db = require('../database/db_connect');
var router = express.Router();
const jwt = require('../modules/jwt');
const shell = require('shelljs');
const Client = require('ssh2-sftp-client');
const path = require("path");

const { Wallets, Gateway } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');
const fs = require("fs");
const ccpPath = path.resolve('/home/user/fabric-samples', '..', '..', 'first-network', 'connection-org1.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);

const cors = require('cors');
router.use(cors({}));

router.post("/", async function (req, res, next) {

  let client = new Client();

  try {

    await client.connect({
      host: "13.125.223.131",
      port: 22,
      user: "ubuntu",
      privateKey : fs.readFileSync("key/hypercerts_fabric_1.ppk")
    }).catch((err) => console.log(err));

    await client.put("hello.txt", "/tmp/hello.txt")
    res.status(200).json({
      "result": true,
      "message": "true"
    });

  } catch (err) {
    console.log(err);
    res.status(200).json({
      "result": false,
      "message": "error"
    });
  }

  try{
    const caInfo = ccp.certificateAuthorities['ca.example.com'];
    const caTLSCACerts = caInfo.tlsCACerts.pem;
    const ca = new FabricCAServices(caInfo.url, { trustedRoots: caTLSCACerts, verify: false }, caInfo.caName);

    const walletPath = path.join(__dirname, 'wallet');
    const wallet = await Wallets.newFileSystemWallet(walletPath);

    let id = req.body.id;
    let pw = req.body.pw;

    const adminExists = await wallet.get(id);
    if (adminExists) {
      console.log('An identity for the admin user "admin" already exists in the wallet');
      res.status(200).json({
        "result": false,
        "message": "이미 존재하는 계정 입니다."
      });
      return;
    }

    const enrollment = await ca.enroll({ enrollmentID: id, enrollmentSecret: pw });
    const x509Identity = {
      credentials: {
        certificate: enrollment.certificate,
        privateKey: enrollment.key.toBytes(),
      },
      mspId: 'Org1MSP',
      type: 'X.509',
    };

    await wallet.put(id, x509Identity);
    console.log('Successfully enrolled and imported the identity of the admin user "admin"');

    res.status(200).json({
      "result": true,
      "message": "true"
    });

  }catch (err){
    console.log(err);
    res.status(200).json({
      "result": false,
      "message": "error"
    });
  }



  // console.log(c);

  // shell.cd('~');
  // if(shell.exec('ls -al').code !== 0){
  //   shell.echo('error: command failed');
  //   shell.exist(1);
  // }
  //


});

router.post('/test', function(req, res) {

  console.log("login");
  console.log(req.body);

  db.query('select * from account', async function (err, rows, field) {
    if (!err) {
      console.log(req.body.id);
      if ((req.body.id === rows[0].id) && (req.body.pw === rows[0].pw)) {
        const token = await jwt.sign(1);

        console.log("token : " + token);

        res.status(200).json({
          "result": true,
          "token" : token
        });
      } else {
        res.status(200).json({
          "result": false,
          "message": "not match"
        });
      }
      // console.log(rows[0].id);

    } else {
      console.log('err : ' + err);
      res.status(200).json({
        "result": false,
        "message": "error"
      });
    }

  })

});

router.get('/auth/ca/admin/logout', async function(req, res, next) {

  let token = req.headers.token;

  console.log(token);

  res.status(200).json({
    "result" : true,
  });

});


router.get('/check', async function(req, res, next) {

  let token = req.headers.token;

  console.log(token);

  const result = await jwt.verify(token);

  console.log(result);

  res.status(200).json({
    "result" : true,
  });

});

router.get('/query', async function(req, res, next) {

  const walletPath = path.join(process.cwd(), 'wallet');
  const wallet = await Wallets.newFileSystemWallet(walletPath);
  console.log(`wallet path : ${walletPath}`);

  //const userExists = await wallet.get("user1");
  if(!userExists){
    console.log("not exist user1");
    res.status(200).json({
      "result" : false,
      "message" : "not exist user1"
    });
  }

  const gateway = new Gateway();
  await gateway.connect(ccp, {wallet, identify: 'user1', discovery: {enabled: false}});

  const network = await gateway.getNetwork('mychannel');

  const contract = network.getContract('fabcar');

  const result = await contract.evaluateTransaction('queryAllCars');


  res.status(200).json({
    "result" : true,
    "message" : "not exist user1",
    "data" : result
  });


  res.status(200).json({
    "result" : true,
  });

});

router.post('/auth/ca/admin/login', function(req, res, next) {

  db.query('select * from account', async function (err, rows, field) {
    if (!err) {
      console.log(req.body.id);
      if ((req.body.id === rows[0].id) && (req.body.pw === rows[0].pw)) {
        const token = await jwt.sign(1);

        console.log("token : " + token);

        res.status(200).json({
          "result": true,
          "token" : token
        });
      } else {
        res.status(200).json({
          "result": false,
          "message": "not match"
        });
      }
      // console.log(rows[0].id);

    } else {
      console.log('err : ' + err);
      res.status(200).json({
        "result": false,
        "message": "error"
      });
    }
  })
});

router.get('/auth/ca/admin/login', function(req, res, next) {

  db.query('select * from account', async function (err, rows, field) {
    if (!err) {

      console.log(req.body.id);

      const token = await jwt.sign(1);

      console.log("token : " + token);

      res.status(200).json({
        "result": true,
        "data" : rows
      });

      // console.log(rows[0].id);

    } else {
      console.log('err : ' + err);
      res.status(200).json({
        "result": false,
        "message": "error"
      });
    }
  })
});


module.exports = router;
