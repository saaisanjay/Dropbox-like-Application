var https = require('https');
var fs = require('fs');
var helmet = require('helmet');
var express = require('express');
var mysql = require('mysql');
var bodyParser = require('body-parser');
var crypto = require('crypto');
morgan      = require('morgan')
jwt    = require('jsonwebtoken')
var multer = require("multer")
const { check, validationResult } = require('express-validator/check');
var con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "secure"
  });
  con.connect(function(err) {
    if (err) throw err;
    console.log("Connected!");
  });
const options = {
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("certificate.pem")
}

const app = express()
app.set('Secret', "nonproductionsecret");

app.use(morgan('dev'));
//Cross Domain Prevention setting X-Permitted-Cross-Domain-Policies
app.use(helmet.permittedCrossDomainPolicies());
// Content Secure policy !
app.use(helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["unsafe-inline'"],
      styleSrc: ["'self'", 'maxcdn.bootstrapcdn.com']
    }
  }))
//EXPECT _ CT Policy !!
app.use(helmet.expectCt({
    enforce: true,
    maxAge: 100
}))
// Feature Policy
app.use(helmet.featurePolicy({
    features: {
        fullscreen: ["'self'"],
        payment: ["'self'"],
        syncXhr: ["'none'"]
    }
}))
// HPKP policy
// This is Http public key pinning policy
//HTTP Public Key Pinning (HPKP)[1] is an Internet security mechanism delivered via an HTTP header which
//allows HTTPS websites to resist impersonation by attackers using mis-issued or otherwise fraudulent certificates.
// In order to do so, it delivers a set of public keys to the client (browser),
//which should be the only ones trusted for connections to this domain.
const ninetyDaysInSeconds = 7776000
app.use(helmet.hpkp({
  maxAge: ninetyDaysInSeconds,
  sha256s: ['AbCdEf123=', 'ZyXwVu456=']
}))
//Prevent CACHE ATTACK
app.use(helmet.noCache())
// REFER policy
// This policy is used for REFERER
//The HTTP referer (originally a misspelling of referrer[1]) is an HTTP header field that identifies the address
//of the webpage (i.e. the URI or IRI) that linked to the resource being requested. By checking the referrer,
//the new webpage can see where the request originated
app.use(helmet.referrerPolicy({ policy: 'same-origin' }))
// DNS prefect Control

app.use(helmet.dnsPrefetchControl())
// FrameGaurd Click jacking prevention
app.use(helmet.frameguard({ action: 'sameorigin' }))
//HIDE poweredby
//Http strict transport policy security policy
//HTTP Strict Transport Security (HSTS) is a web security policy mechanism that helps to protect
//websites against protocol downgrade attacks and cookie hijacking. It allows
// web servers to declare that web browsers (or other complying user agents) should interact with it using
//only secure HTTPS connections, and never via the insecure HTTP protocol. HSTS is an IETF standards track protocol and is specified
app.use(helmet.hidePoweredBy())
//HSTS transport security
const sixtyDaysInSeconds = 5184000
app.use(helmet.hsts({
  maxAge: sixtyDaysInSeconds
}))
//IE download prevention X-DOWNLOAD-OPtion
app.use(helmet.ieNoOpen())
//NO sniff
app.use(helmet.noSniff())
//XSS filter
app.use(helmet.xssFilter())

app.use(bodyParser.urlencoded({ extended: false }))

app.use(bodyParser.json())

app.use(express.static('public'))
app.get("/", (req,res)=>{
    res.send("HELO")
})
const protectedRoutes = express.Router()
protectedRoutes.use((req,res,next)=>{
    var token = req.headers['access-token'];

    if (token) {

      jwt.verify(token, app.get('Secret'), (err, decoded) =>{
        if (err) {
          return res.json({ message: 'invalid token' });
        } else {
          req.decoded = decoded;
          next();
        }
      });

    } else {

      res.send({

          message: 'No token provided.'
      });

    }
})
var storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, './my-uploads')
    },
    filename: function (req, file, cb) {
      cb(null, file.fieldname + '-' + Date.now())
    }
  })
  var upload = multer({ storage: storage })

protectedRoutes.post('/uploadFile',upload.single('mfile'), function (req,res){
    var username = req.body.email;
    if(req.file == undefined){
        res.json({"message":"Please select a File"})
    }
    var filename = req.file.originalname
    var dup = req.file.filename;
    var filepath = req.file.path;
    var sql = "SELECT userid FROM Users WHERE username='"+username+"'";
    con.query(sql, function(err,result){
        if(err){
            res.json({"message":"Upload error"})
        }
        console.log(result)
        if(result.length != 0){
            var userid = result[0].userid;
            var sql = "INSERT INTO Files (UserID, FileName, FileLocation,duplicateName) VALUES ('"+userid+"','"+filename+"','"+filepath+"','"+dup+"')";
            con.query(sql, function(err,result){
                if(err){
                    res.json({"message":"Upload error"})
                }else{
                    res.json({"message": "Success"})
                }
            })
        }
    })
})
protectedRoutes.post('/listmyFiles', [check('email').isEmail(),check('email').isAscii()],function(req,res){
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        res.json({"message":"Validation Error, input is either not assci or in required format"})
    }
    else{
        var username = req.body.email;
    var sql = "SELECT userid FROM Users WHERE username='"+username+"'";
    con.query(sql, function(err,result){
        if (err){
            res.json({"message":"List FIles error"});
        }
        if(result.length != 0){
            var userid =  result[0].userid;
            var sql = "SELECT FileName,FileID from Files WHERE UserID='"+userid+"'";
            con.query(sql, function(err, result){
                if(err){
                    res.json({"message": "Display error"});
                }
                res.json({"message":"Success", "result": result})
            })
        }
    })

    }

})
protectedRoutes.post('/deleteFile',[check('email').isEmail(),check('email').isAscii(),check('fileid').isNumeric()],(req,res)=>{
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        res.json({"message":"Validation Error, input is either not assci or in required format"})
    }
    else{
        var username = req.body.email;
        var fileid = req.body.fileid;
        var sql = "SELECT userid FROM Users WHERE username='"+username+"'";
        con.query(sql, function(err,result){
            if (err){
                res.json({"message":"List FIles error"});
            }
            if(result.length != 0){
                var userid =  result[0].userid;
                var sql = "SELECT * from Files WHERE UserID='"+userid+"' and FileID='"+fileid+"'";
                con.query(sql, function(err, result){
                    if(err){
                        res.json({"message": "Display error"});
                    }
                    if(result.length != 0){
                        createdUSER = result[0].UserID;
                        if (createdUSER === userid){
                            console.log(result);
                            fs.unlinkSync(__dirname+"/"+result[0].FileLocation);
                            var sq = "DELETE FROM Files WHERE FileID='"+result[0].FileID+"'";
                            con.query(sq, function(req, ress){
                                if(err){
                                    res.json({"message":"Delete Error"})
                                }
                                else{
                                    res.json({"message":"File Deleted!"})
                                }
                            })
                        }
                    }
                })
            }
        })
    }

   })
protectedRoutes.post("/downloadFile",[check('email').isEmail(),check('email').isAscii(),check('fileid').isNumeric()], (req,res)=> {
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        res.json({"message":"Validation Error, input is either not assci or in required format"})
    }
    else{
        var username = req.body.email;
    var fileid = req.body.fileid;
    var sql = "SELECT userid FROM Users WHERE username='"+username+"'";
    con.query(sql, function(err,result){
        if (err){
            res.json({"message":"List FIles error"});
        }
        if(result.length != 0){
            var userid =  result[0].userid;
            var sql = "SELECT * from Files WHERE UserID='"+userid+"' and FileID='"+fileid+"'";
            con.query(sql, function(err, result){
                if(err){
                    res.json({"message": "Display error"});
                }
                if(result.length != 0){
                    createdUSER = result[0].UserID;
                    if (createdUSER === userid){
                        console.log(result);
                        res.download(__dirname+"/"+result[0].FileLocation)
                    }
                }
            })
        }
    })
    }

})
app.use('/api',protectedRoutes);
app.post("/register",[check('email').isEmail(),check('email').isAscii(),check('password').isLength({min:5})], function(req,res){
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        res.json({"message":"Validation Error, input is either not assci or in required format"})
    }
    else{
        var password = crypto.createHash('sha256').update(req.body.password).digest('base64');
    var sql = "INSERT INTO Users (username, password,roleid) VALUES ('"+req.body.email+"','"+ password+"',2)";
    con.query(sql, function(err, result){
        if (err){
            res.json({"message":"ERROR"})
        }
        console.log("1 record inserted")
        res.json({"message":"DATA INSERTED"})
    })
    }

})

app.post("/login",[check('email').isEmail(),check('email').isAscii(),check('password').isLength({min:5})] ,function(req,res){
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        res.json({"message":"Validation Error, input is either not assci or in required format"})
    }
    else{
        var password = crypto.createHash('sha256').update(req.body.password).digest('base64');
    var sql = "SELECT * FROM Users WHERE username = '"+req.body.email+"' and password='"+ password+"'";
    con.query(sql, function (err, result, fields) {
        if (err){
            res.json({"message": "couldn't login"})
        }
        console.log(result)
        if (result.length != 0){

            const payload = {

                check:  true

              };

              var token = jwt.sign(payload, app.get('Secret'), {
                    expiresIn: 1440 // expires in 24 hours

              });
              res.json({"message":"valid", "token":token});
        }
        else{
            res.json({"message":"invalid"});
        }
    })
    }

})


app.listen(8000);
https.createServer(options, app).listen(8080);


/*citation/referene


https://stackoverflow.com/questions/29659154/what-is-the-best-way-to-upload-files-in-a-modern-browser

https://github.com/blueimp/jQuery-File-Upload


https://github.com/leonardo-wilhelm/helmet_project


https://stackoverflow.com/questions/2353818/how-do-i-get-started-with-node-js

https://stackoverflow.com/questions/49223125/how-to-override-a-helm-value?rq=1

https://stackoverflow.com/questions/4088723/validation-library-for-node-js

https://stackoverflow.com/questions/13598837/node-js-express-form-clears-on-submission/13599609

https://stackoverflow.com/questions/13598837/node-js-express-form-clears-on-submission/13599609
*/
