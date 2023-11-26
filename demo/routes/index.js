var express = require('express');
const db = require('../database/db_connect');
var router = express.Router();
const jwt = require('../modules/jwt');
const shell = require('shelljs');
//const Client = require('ssh2-sftp-client');
const path = require("path");

const { Wallets, Gateway } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');
const fs = require("fs");
const ccpPath = path.resolve('../config/connection-org1.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);

const cors = require('cors');
router.use(cors({}));


router.post("/", async function (req, res, next) {

  //let client = new Client();

  // try {
  //
  //   await client.connect({
  //     host: "13.125.223.131",
  //     port: 22,
  //     user: "ubuntu",
  //     privateKey : fs.readFileSync("key/hypercerts_fabric_1.ppk")
  //   }).catch((err) => console.log(err));
  //
  //   await client.put("hello.txt", "/tmp/hello.txt")
  //   res.status(200).json({
  //     "result": true,
  //     "message": "true"
  //   });
  //
  // } catch (err) {
  //   console.log(err);
  //   res.status(200).json({
  //     "result": false,
  //     "message": "error"
  //   });
  // }

  //1. admin 인증서가 발행되어 있지 않으면 인증서 발행
  //2. 발행된 인증서를 사용하여 유저 생성


  try{

    const caInfo_tls = ccp.certificateAuthorities['ca.tls.hypercerts.com'];
    const caInfo_org1 = ccp.certificateAuthorities['ca.org1.hypercerts.com'];
    const caInfo_org2 = ccp.certificateAuthorities['ca.org2.hypercerts.com'];
    const caInfo_orderer = ccp.certificateAuthorities['ca.orderer.hypercerts.com'];

    const ca_tls = new FabricCAServices(caInfo_tls.url, { trustedRoots: caInfo_tls.tlsCACerts.pem, verify: false }, caInfo_tls.caName);
    const ca_org1 = new FabricCAServices(caInfo_org1.url, { trustedRoots: caInfo_org1.tlsCACerts.pem, verify: false }, caInfo_org1.caName);
    const ca_org2 = new FabricCAServices(caInfo_org2.url, { trustedRoots: caInfo_org2.tlsCACerts.pem, verify: false }, caInfo_org2.caName);
    const ca_orderer = new FabricCAServices(caInfo_orderer.url, { trustedRoots: caInfo_orderer.tlsCACerts.pem, verify: false }, caInfo_orderer.caName);

    const walletPath = path.join(__dirname, 'wallet');
    const wallet = await Wallets.newFileSystemWallet(walletPath);

    db.query('select * from ca', async function (err, rows, field) {
      if (!err) {
        for(let i=0;i<rows.length;i++){

          if(rows[i].net_group === "tls"){
            console.log("tls");

            // const enrollment = await ca_tls.enroll({ enrollmentID: rows[i].id, enrollmentSecret: rows[i].id + "pw"});
            // const x509Identity = {
            //   credentials: {
            //     certificate: enrollment.certificate,
            //   },
            // };
            //
            // await wallet.put(rows[i].id, x509Identity);

          }else if(rows[i].net_group === "org1"){

            console.log("org1");

            // const enrollment = await ca_org1.enroll({ enrollmentID: rows[i].id, enrollmentSecret: rows[i].id + "pw"});
            // const x509Identity = {
            //   credentials: {
            //     certificate: enrollment.certificate,
            //   },
            // };
            //
            // await wallet.put(rows[i].id, x509Identity);

          }else if(rows[i].net_group === "org2"){

            console.log("org2");

            // const userExists = await wallet.get(rows[i].id);
            // if(!userExists){
            //
            //   const enrollment = await ca_org2.enroll({ enrollmentID: rows[i].id, enrollmentSecret: rows[i].id + "pw"});
            //
            //   const x509Identity = {
            //     credentials: {
            //       certificate: enrollment.certificate,
            //     },
            //   };
            //
            //   await wallet.put(rows[i].id, x509Identity);
            // }

          }else{

            console.log("orderer");

            // const userExists = await wallet.get(rows[i].id);
            // if(!userExists){
            //
            //   const enrollment = await ca_orderer.enroll({ enrollmentID: rows[i].id, enrollmentSecret: rows[i].id + "pw"});
            //
            //   const x509Identity = {
            //     credentials: {
            //       certificate: enrollment.certificate,
            //     },
            //   };
            //
            //   await wallet.put(rows[i].id, x509Identity);
            // }


          }

        }

        res.status(200).json({
          "result": true,
        });
      } else {
        res.status(200).json({
          "result": false,
          "message": "not match"
        });
      }

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

//인증서 생성
router.post('/tlsca/ca/create', function(req, res) {

  console.log("/tlsca/ca/create");
  console.log(req.body);

  let user_id = req.body.id; //아이디
  let group = req.body.group; //소속
  let role = req.body.role; //권한 //admin, client, peer
  let today = new Date();
  let month = today.getMonth() + 1;
  let date = today.getFullYear() + "/" + month + "/" +  today.getDate(); //현재 시간 ex) 2023/11/20

  let query = "insert into `ca` (`id`, `net_group`, `create_time`, `role`) values ('"+user_id+"', '"+group+"', '"+date+"', '"+role+"');"
  db.query(query, async function (err, rows, field) {
    if (!err) {
        res.status(200).json({
          "result": true,
        });
    } else {
      console.log('err : ' + err);
      res.status(200).json({
        "result": false,
        "message": "error"
      });
    }

  })

});

//인증서 리스트 조회
router.get('/tlsca/ca/list', function(req, res) {

  console.log("/tlsca/ca/list");

  db.query('select * from ca', async function (err, rows, field) {
    if (!err) {
        res.status(200).json({
          "result": true,
          "list" : rows
        });
      } else {
        res.status(200).json({
          "result": false,
          "message": "not match"
        });
      }
      // console.log(rows[0].id);

    });
});

//인증서 삭제
router.delete('/tlsca/ca/delete/:pk', function(req, res) {

  console.log(req.params.pk);

  var number = req.params.pk;
  let query = "delete from ca where pk = "+number;
  db.query(query, async function (err, rows, field) {
    if (!err) {
      res.status(200).json({
        "result": true,
      });
    } else {
      res.status(200).json({
        "result": false,
        "message": "error"
      });
    }
    // console.log(rows[0].id);

  });
});

//인증서 업데이트 및 수정
router.post('/tlsca/ca/update/:pk', function(req, res) {

  console.log(req.params.pk);
  console.log(req.body);
  var number = req.params.pk;

  let query = "update ca set id='"+req.body.id+"', net_group='"+req.body.group +"', role='"+req.body.role +"' where pk="+number;
  console.log(query);
  db.query(query, async function (err, rows, field) {
    if (!err) {
      res.status(200).json({
        "result": true,
      });
    } else {
      res.status(200).json({
        "result": false,
        "message": "error"
      });
    }
    // console.log(rows[0].id);

  });
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
