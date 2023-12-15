var express = require('express');
const db = require('../database/db_connect');
var router = express.Router();
const jwt = require('../modules/jwt');
const shell = require('shelljs');
const path = require("path");

const fs = require("fs");

const cors = require('cors');
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

router.get('/', async function(req, res) {

  console.log("/");
  res.status(200).json({
    "result": true,
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

  db.query('select * from node order by organization ASC', async function (err, rows, field) {
    if (!err) {
      console.log(rows);
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

//노드 추가
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

  try{

    let id = req.body.id; //아이디
    let pw = req.body.password; //비밀번호
    let ca_name = req.body.ca_name;
    let organization = req.body.organization; //ca 이름
    let role = req.body.role; //권한 client, peer
    let port = req.body.port; //권한 client, peer
    let today = new Date();
    let month = today.getMonth() + 1;
    let date = today.getFullYear() + "/" + month + "/" + today.getDate(); //현재 시간 ex) 2023/11/20

    pw = cipher(pw);

    let checkQuery = "select * from node where id='"+id+"' and ca_name='" + ca_name +"' and organization ='" + organization + "'";
    db.query(checkQuery, async function (err, rows, field) {

      if(rows.length !== 0){
        res.status(400).json({
          "result": true,
          "message" : "이미 해당 노드가 존재합니다."
        });
      }else{

        let query = "insert into node (`id`,`pw`,`organization`,`role`,`create_time`, `ca_name`, `port`) values ('"+id+"','"+pw+"','"+organization+"','"+role+"','"+date+"','"+ca_name+"','"+port+"')";
        console.log(query);
        db.query(query, async function (err, rows, field) {

          if (!err) {

            db.query('SELECT LAST_INSERT_ID() as id from node', function (error, results, fields) {
              if (error) throw error;
              const autoIncrementValue = results[0].id;

              res.status(200).json({
                "result": true,
                "pk": autoIncrementValue

              });
            });
          }else {
            console.log('err : ' + err);
            res.status(400).json({
              "result": false,
              "message": "error"
            });
          }
        })
      }
    })
  }catch (err){
    console.log(err);
  }
});

//노드 삭제
router.delete('/tlsca/node/delete/:pk', async function(req, res) {

  let token = req.headers.token;

  const result = await jwt.verify(token); // verify 함수 호출
  if(result < 0){
    res.status(401).json({
      "result": false,
      "message" : "invalid token"
    });
    return;
  }

  try{
    let selectQuery = "select * from node where pk='"+req.body.list[i]+"'";
    db.query(selectQuery, async function (err, rows, field) {

      if (err) {
        console.log('err : ' + err);
        res.status(200).json({
          "result": false,
          "message": "error"
        });
      }else{
        let ca_name_origin = rows[0].ca_name.split("-");
        shell.exec('/work/hypercerts-network/organizations/fabric-ca/node/deleteCert.sh ' + rows[0].id + " " + rows[0].organization + " " + ca_name_origin[1]);
      }
    })


    for(let i = 0;i < req.body.list.length;i++){

      let query = "delete from node where pk='"+req.body.list[i]+"'";
      db.query(query, async function (err, rows, field) {

        if (err) {
          console.log('err : ' + err);
          res.status(200).json({
            "result": false,
            "message": "error"
          });
        }
      })
    }

    res.status(200).json({
      "result": true,
    });

  }catch (err){
    console.log(err);
  }
});

//인증서 생성
router.post('/tlsca/certificate/create', async function(req, res) {

  let token = req.headers.token;

  const result = await jwt.verify(token); // verify 함수 호출
  if (result < 0) {
    res.status(401).json({
      "result": false,
      "message": "invalid token"
    });
    return;
  }

    for(let i = 0;i < req.body.list.length;i++){

      let query = "select * from node where pk='"+req.body.list[i]+"'";
      db.query(query, async function (err, rows, field) {

        if (!err) {
          let pw = decipher(rows[0].pw);
          let ca_name_origin = rows[0].ca_name.split("-");
          console.log('/work/hypercerts-network/organizations/fabric-ca/node/webEnrollScript.sh ' +rows[0].role+ " "+ rows[0].id + " "+ pw + " " + rows[0].ca_name + " " + rows[0].port + " " + ca_name_origin[1] +" " + rows[0].organization);
          shell.exec('/work/hypercerts-network/organizations/fabric-ca/node/webEnrollScript.sh ' +rows[0].role+ " "+ rows[0].id + " "+ pw +" " + rows[0].ca_name + " " + rows[0].port + " " + ca_name_origin[1] + " " + rows[0].organization);
        }
        else {
          console.log('err : ' + err);
          res.status(200).json({
            "result": false,
            "message": "error"
          });
        }
      })
    }

    res.status(200).json({
      "result": true,
      "message": "인증서 생성 성공",
    });

});

//node 인증서 다운로드
router.get('/tlsca/node/get/:pk', async function(req, res) {


  let query = "select * from node where pk='"+req.params.pk+"'";

  console.log(query);
  db.query(query, async function (err, rows, field) {
    if (!err) {

      let file_name = rows[0].organization + "-" + rows[0].id +"-" + "msp" + ".zip";
      console.log(file_name);
      let file_path = "../wallet/";
      fs.readFile(file_path + file_name, function (err, data) {
        if (err) {
          res.writeHead(404, {'Content-Type': 'text/html'});
          return res.end('File not found');
        }

        res.setHeader('Content-disposition', 'attachment; filename=' + file_name); // 다운로드 받을 때의 파일명 설정
        res.setHeader('Content-Type', 'application/zip');
        res.end(data);
      });

    } else {
      res.status(400).json({
        "result": false,
        "message": "error"
      });
    }

  });
});

//인증서 배포
router.get('/tlsca/deploy', async function(req, res) {

  let token = req.headers.token;

  const result = await jwt.verify(token); // verify 함수 호출
  if (result < 0) {
    res.status(401).json({
      "result": false,
      "message": "invalid token"
    });
    return;
  }

  try{
    
    shell.exec('/work/hypercerts-network/tlssend.sh');

    res.status(200).json({
      "result": true,
      "message": "배포 성공"
    });

  }catch (err){
    console.log(err);
    res.status(400).json({
      "result": false,
      "message": "배포 에러"
    });
  }
});

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
