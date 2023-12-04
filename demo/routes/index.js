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

const IV_LENGTH = 16 // For AES, this is always 16
const ENCRYPTION_KEY =
    process.env.ENCRYPTION_KEY || 'abcdefghijklmnop'.repeat(2) // Must be 256 bits (32 characters)

const cipher = (text) => {
  const iv = crypto.randomBytes(IV_LENGTH)
  const cipher = crypto.createCipheriv(
      'aes-256-cbc',
      Buffer.from(ENCRYPTION_KEY),
      iv,
  )
  const encrypted = cipher.update(text)

  return (
      iv.toString('hex') +
      ':' +
      Buffer.concat([encrypted, cipher.final()]).toString('hex')
  )
}

const decipher = (text) => {
  const textParts = text.split(':')
  const iv = Buffer.from(textParts.shift(), 'hex')
  const encryptedText = Buffer.from(textParts.join(':'), 'hex')
  const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      Buffer.from(ENCRYPTION_KEY),
      iv,
  )
  const decrypted = decipher.update(encryptedText)

  return Buffer.concat([decrypted, decipher.final()]).toString()
}


//ca 조회
router.get('/tlsca/ca/list', async function(req, res) {

  console.log("/tlsca/ca/list");
  let token = req.headers.token;

  const result = await jwt.verify(token); // verify 함수 호출
  if(result < 0){
    res.status(401).json({
      "result": false,
      "message" : "invalid token"
    });
    return;
  }

  db.query('select * from ca', async function (err, rows, field) {
    if (!err) {
      res.status(200).json({
        "result": true,
        "list" : rows
      });
    } else {
      res.status(400).json({
        "result": false,
        "message": "not match"
      });
    }
    // console.log(rows[0].id);
  });
});

//ca 추가
router.post('/tlsca/ca/create', async function(req, res) {

  console.log("/tlsca/ca/create");
  console.log(req.body);

  let token = req.headers.token;

  const result = await jwt.verify(token); // verify 함수 호출
  if(result < 0){
    res.status(401).json({
      "result": false,
      "message" : "invalid token"
    });
    return;
  }

  let port = req.body.port;
  let ca_name = req.body.ca_name; //ca_name
  let ca_origin_name = req.body.ca_origin_name; //ca_origin_name
  let admin_id = req.body.id; //ca_origin_name
  let admin_pw = req.body.pw; //ca_origin_name

  let today = new Date();
  let month = today.getMonth() + 1;
  let date = today.getFullYear() + "/" + month + "/" +  today.getDate(); //현재 시간 ex) 2023/11/20

  //포트 확인해서 추가하려는 포트가 이미 존재하면 에러 발생
  let portCheckQuery = "select port from ca where port='"+port+"'";
  db.query(portCheckQuery
      , function (err, rows){
        if(rows.length !== 0){
            res.status(400).json({
              "result": false,
              "message" : "이미 존재하는 포트 입니다."
            });
        }else{
          //관리자 계정 등록
          shell.exec('/work/hypercerts-network/organizations/fabric-ca/nodeScript/adminEnroll.sh ' +"admin"+ " " + admin_id + " "+ admin_pw + " " + ca_name + " " + port + " " + ca_origin_name);

          let caQuery = "insert into ca (`port`,`ca_name`,`ca_origin_name`) values ('"+port+"', '"+ca_name+"', '"+ca_origin_name+"');";

          db.query(caQuery
              , async function (err){
                if(err){
                  res.status(500).json({
                    "result":false,
                    "message" : "db error"
                  });
                }
              })

          admin_pw = cipher(admin_pw);
          let query = "insert into node (`id`,`pw`,`ca_origin_name`,`role`,`create_time`) values ('"+admin_id+"', '"+admin_pw+"', '"+ca_origin_name+"','"+"admin"+"', '"+date+"');"
          db.query(query, async function (err, rows, field) {
            if (!err) {
              res.status(200).json({
                "result": true,
              });
            } else {
              console.log('err : ' + err);
              res.status(400).json({
                "result": false,
                "message": "error"
              });
            }
          })
        }
    })

});

//ca 삭제?
//ca 삭제 //db 에서만 삭제 조치
router.delete('/tlsca/ca/delete/:port', async function(req, res) {

  console.log(req.params.pk);

  let token = req.headers.token;

  const result = await jwt.verify(token); // verify 함수 호출
  if(result < 0){
    res.status(401).json({
      "result": false,
      "message" : "invalid token"
    });
    return;
  }

  var port = req.params.port;
  let query = "delete from ca where port = "+port;
  db.query(query, async function (err, rows, field) {
    if (!err) {
      res.status(200).json({
        "result": true,
      });
    } else {
      res.status(400).json({
        "result": false,
        "message": "error"
      });
    }
    // console.log(rows[0].id);
  });
});

//노드 조회
//node 리스트 조회
router.get('/tlsca/node/list', async function(req, res) {

  console.log("/tlsca/node/list");
  let token = req.headers.token;

  const result = await jwt.verify(token); // verify 함수 호출
  if(result < 0){
    res.status(401).json({
      "result": false,
      "message" : "invalid token"
    });
    return;
  }

  db.query('select * from node', async function (err, rows, field) {
    if (!err) {
      res.status(200).json({
        "result": true,
        "list" : rows
      });
    } else {
      res.status(400).json({
        "result": false,
        "message": "not match"
      });
    }
    // console.log(rows[0].id);
  });
});

//노드 추가 및 인증서 생성
router.post('/tlsca/node/create', async function(req, res) {

  console.log("/tlsca/node/create");
  console.log(req.body);

  let token = req.headers.token;

  const result = await jwt.verify(token); // verify 함수 호출
  if(result < 0){
    res.status(401).json({
      "result": false,
      "message" : "invalid token"
    });
    return;
  }

  let id = req.body.id; //아이디
  let pw = req.body.password; //비밀번호
  let ca_origin_name = req.body.ca; //ca 이름
  let role = req.body.role; //권한 client, peer
  let today = new Date();
  let month = today.getMonth() + 1;
  let date = today.getFullYear() + "/" + month + "/" +  today.getDate(); //현재 시간 ex) 2023/11/20

// 암호화 메서드

  //ca_origin_name을 통해서 ca_name과 port 값쿼리
  let ca_name;
  let port;
  let admin_id;
  let admin_pw;

  let getCaPortQuery = "select * from ca where CA_ORIGIN_NAME='"+ca_origin_name+"'";
  db.query(getCaPortQuery, async function (err, rows, fields){
    if(err){
      res.status(401).json({
        "result": false,
        "message" : "db error"
      });
    } else {
      if(rows.length === 0){
        res.status(400).json({
          "result": false,
          "message" : "존재하지 않는 ca에 node 추가를 시도하고 있습니다."
        });
        return;
      }

      ca_name = rows[0].ca_name;
      port = rows[0].port;

      let alreadyIdCheck = "select * from node where CA_ORIGIN_NAME='"+ca_origin_name+"' and id='"+id +"'";
      db.query(alreadyIdCheck, async function (err, rows, fields) {
        if(rows.length === 0){

          let getAdminQuery = "select * from node where CA_ORIGIN_NAME='"+ca_origin_name+"' and " + "role='admin'";
          db.query(getAdminQuery, async function (err, rows, fields){
            admin_id = rows[0].id;
            admin_pw = decipher(rows[0].pw);
          });


          shell.exec('/work/hypercerts-network/organizations/fabric-ca/nodeScript/adminEnroll.sh ' +role+ " "+ id + " "+ pw + " " + ca_name + " " + port + " " + ca_origin_name + " " + admin_id + " " + admin_pw);

          pw = cipher(pw);

          let query = "insert into node (`id`,`pw`,`ca_origin_name`,`role`,`create_time`) values ('"+id+"', '"+pw+"', '"+ca_origin_name+"','"+role+"', '"+date+"');"
          db.query(query, async function (err, rows, field) {
            if (!err) {
              res.status(200).json({
                "result": true,
              });
            } else {
              console.log('err : ' + err);
              res.status(400).json({
                "result": false,
                "message": "error"
              });
            }
          })

        }else{
          res.status(400).json({
            "result": false,
            "message" : "이미 존재하는 id 추가를 시도하고 있습니다."
          });
        }
      });

    }
  });
});

//인증서 업데이트 및 수정은 어려움 차라리 재 인증서 생성은 가능
// router.post('/tlsca/ca/update/:pk', async function(req, res ) {
//
//   let token = req.headers.token;
//
//   const result = await jwt.verify(token); // verify 함수 호출
//   if(result < 0){
//     res.status(401).json({
//       "result": false,
//       "message" : "invalid token"
//     });
//     return;
//   }
//
//   var number = req.params.pk;
//
//   let query = "update ca set id='"+req.body.id+"', net_group='"+req.body.group +"', role='"+req.body.role +"' where pk="+number;
//   console.log(query);
//   db.query(query, async function (err, rows, field) {
//     if (!err) {
//       res.status(200).json({
//         "result": true,
//       });
//     } else {
//       res.status(400).json({
//         "result": false,
//         "message": "error"
//       });
//     }
//     // console.log(rows[0].id);
//
//   });
// });

//node 인증서 다운로드?
router.get('/tlsca/ca/get/:id', async function(req, res) {

  let token = req.headers.token;

  const result = await jwt.verify(token); // verify 함수 호출
  if (result < 0) {
    res.status(401).json({
      "result": false,
      "message": "invalid token"
    });
    return;
  }

  console.log(req.params.id);
  res.setHeader('Content-type', "text/html"); // 파일 형식 지정
  res.download(`./wallet/${req.params.id}`, (err) => {
    if (err) {
      // 에러 처리
      res.status(404).send('File not found');
    } else {
      console.log('File downloaded successfully');
    }
  });

});

//체인코드 연동 준비
// router.get('/query', async function(req, res, next) {
//
//   const walletPath = path.join(process.cwd(), 'wallet');
//   const wallet = await Wallets.newFileSystemWallet(walletPath);
//   console.log(`wallet path : ${walletPath}`);
//
//   //const userExists = await wallet.get("user1");
//   if(!userExists){
//     console.log("not exist user1");
//     res.status(200).json({
//       "result" : false,
//       "message" : "not exist user1"
//
//     });
//   }
//
//   const gateway = new Gateway();
//   await gateway.connect(ccp, {wallet, identify: 'user1', discovery: {enabled: false}});
//
//   const network = await gateway.getNetwork('mychannel');
//
//   const contract = network.getContract('fabcar');
//
//   const result = await contract.evaluateTransaction('queryAllCars');
//
//
//   res.status(200).json({
//     "result" : true,
//     "message" : "not exist user1",
//     "data" : result
//   });
//
// });


router.post('/auth/ca/admin/login', function(req, res, next) {

  let query = "select * from account where account='"+ req.body.id +"'";
  db.query(query, async function (err, rows, field) {
    if (!err) {
      console.log(req.body.id);
      if ((req.body.pw === rows[0].pw)) {
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

module.exports = router;
