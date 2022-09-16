var express = require('express');
var router = express.Router();
var mysql = require('mysql')
var bcrypt = require('bcrypt')
var con = require('../database/con')

/* GET home page. */
router.get('/', function(req, res, next) {
  if(req.session.flag == 1){
    req.session.destroy()
    res.render('index', { title: 'Testing Auth with NodeJS', message : 'email sudah digunakan',flag :1});
  }else if (req.session.flag == 2){
    req.session.destroy()
    res.render('index', { title: 'Testing Auth with NodeJS', message : 'Daftar Berhasil!, Silahkan Login', flag : 0});
  }else if (req.session.flag == 3){
    req.session.destroy()
    res.render('index', { title: 'Testing Auth with NodeJS', message : 'Konfirmasi password tidak sama!', flag: 1 });
  }else if (req.session.flag == 4){
    req.session.destroy()
    res.render('index', { title: 'Testing Auth with NodeJS', message : 'Email atau Password SALAH!', flag : 1 });
  }else {
    res.render('index', { title: 'Testing Auth with NodeJS' });  
  }
  
});

//Handle POST request for user Registration
router.post('/auth_reg', function (req,res,next){
  let fullname = req.body.fullname
  let email = req.body.email
  let password = req.body.password
  let cpassword = req.body.cpassword

  if (cpassword == password){
    let sql = 'select * from user where email = ?;'
    
    con.query(sql,[email],function(err,result,fields){
      if(err) throw err

      if(result.length > 0){
        req.session.flag = 1
        res.redirect('/')
      }else {
        let hashpassword = bcrypt.hashSync(password, 10)
        let sql = 'insert into user(fullname,email,password) values(?,?,?);'

        con.query(sql,[fullname,email,hashpassword],function(err,result,fields){
          if(err) throw err
          req.session.flag = 2
          res.redirect('/')
        })
      }
    })
  }else{
    req.session.flag = 3
    res.redirect('/')
  }
})

//Handle POST request for user Login
router.post('/auth_login',function (req,res,next){
  
  let email = req.body.email
  let password = req.body.password

  let sql = 'select * from user where email = ?;'
  con.query(sql,[email],function(err,result,fields){
    if(err) throw err

    if(result.length && bcrypt.compareSync(password,result[0].password)){
      
      req.session.email = email
      res.redirect('/home')
    }else {
      req.session.flag = 4
      res.redirect('/')
    }
  })
})

//Route for home page
router.get('/home', function(req,res,next){
  res.render('home',{message : 'Welcome, ' + req.session.email})
})
router.get('/logout',function(req,res,next){
  if(req.session.email){
    req.session.destroy()
  }
  res.redirect('/')
})
module.exports = router;
