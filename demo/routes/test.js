const fs = require("fs");

fs.readFile('../fabric-ca-server-config.yaml', 'utf8', function(err, data){

    let dataArray = data.split('\n');
    // for(let i = 0;i<10;i++){
    //     console.log(dataArray[i]);
    // }
    const dataIndexToModify = 310;
    console.log(dataArray[dataIndexToModify])

    dataArray[dataIndexToModify] = "   cn: test-ca-server"

    const modifiedData = dataArray.join('\n');
    fs.writeFile('../fabric-ca-server-config.yaml', modifiedData, 'utf8', (err) => {
        if (err) {
            console.error('파일에 쓰는 도중 오류 발생:', err);
        } else {
            console.log('파일의 202번째 데이터가 성공적으로 수정되었습니다.');
        }
    });
});


// console.log("data");