var express = require('express')
var session = require('express-session')
let setting = require('./setting.json')
const fetch = require('node-fetch')
const fs = require('fs')
var app = express()

// const app = require("https-localhost")()
// process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'

const oxd = require('oxd-node')(setting.oxd_setting);

let sess = session({
    secret: 'mflv[FvgvHd:Nfugvruwv',
    resave: false,
    saveUninitialized: true
})

var bodyParser = require('body-parser')

app.use(sess)
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

app.use(express.static("public"));

app.set('view engine', 'ejs')

let getTokenByCode = function(code, state){
    return new Promise((resolve, reject) => {
        oxd.get_tokens_by_code({
            oxd_id: setting.oxd_id,
            code: code,
            state: state
        }, (err, response) => {
            if (err) {
                console.log('Error : ', err);
                resolve({ error: err })
            }

            resolve(response)
        });   
    })
        
    
}


let getUserInfo = function(access_token){
    return new Promise((resolve, reject) => {
        oxd.get_user_info({
            oxd_id: setting.oxd_id,
            access_token: access_token
        }, (err, response) => {
            if (err) {
                console.log('getUserInfo Error : ', err);
                resolve({ "error": err })
            }
            resolve(response)
        });
    })
}

let getTokenByRefreshToken = function(sess){
    return new Promise((resolve, reject) => {

        oxd.get_access_token_by_refresh_token({
            oxd_id: setting.oxd_id,
            refresh_token: sess.refresh_token,
            scope: setting.reg.scope
        }, (err, response) => {
            if (err) {
                console.log('getAccessTokenByRTK Error : ', err);
                resolve({ "error": err })
            }

            resolve(response)
        });
    })
}


let isSigned = function(sess){
    return new Promise((resolve, reject) => {
        oxd.introspect_access_token({
            oxd_id: setting.oxd_id,
            access_token: sess.access_token
          }, (err, response) => {
            if(err){
                getTokenByRefreshToken(sess).then(newToken => {
                    if(newToken.data.access_token){
                        sess.access_token = newToken.data.access_token
                        sess.refresh_token = newToken.data.refresh_token
                        resolve(true)
                    }
                    else resolve(false)
                })
            }
            else{
                if(response.data.active){
                    resolve(true)
                } 
                else{
                    getTokenByRefreshToken(sess).then(newToken => {
                        if(newToken.data.access_token){
                            sess.access_token = newToken.data.access_token
                            sess.refresh_token = newToken.data.refresh_token
                            resolve(true)
                        }
                        else resolve(false)
                    })
                }
            }
            
          });
    })
}


app.get('/', async (req, res) => {
    let sess = req.session.oxdapi
    if(sess){
        let signed = await isSigned(sess)
        
        if(signed){
            res.render('index', { 'setting': setting, 'uprofile': sess.uprofile })
        }
        else {
            req.session.destroy();
            res.render('index', { 'setting': setting, 'uprofile': {} })
        }
        
    }
    else res.render('index', { 'setting': setting, 'uprofile': {} })
})


app.get('/callback', async (req, res) => {
    if(req.query.code && req.query.state){
        // console.log(req.query.code, req.query.state)
        let sess = req.session.oxdapi
        if (!sess) {
            sess = req.session.oxdapi = {}
        }
        let accToken = await getTokenByCode(req.query.code, req.query.state)
        if(accToken.data){
            sess.access_token = accToken.data.access_token
            sess.refresh_token = accToken.data.refresh_token
            let uprofile = await getUserInfo(accToken.data.access_token)
            if(uprofile.data){
                sess.uprofile = uprofile.data.claims
            }
            res.redirect("/")
        }
        else res.render('index', { 'setting': setting , 'uprofile': {}})
    }
    else{
        req.session.destroy();
        res.render('index', { 'setting': setting , 'uprofile': {}})
    }
})


app.post('/register', (req, res) => {
    data = req.body
    oxd.register_site({
        op_host: setting.op_host,
        authorization_redirect_uri: data.authorization_redirect_uri,
        post_logout_redirect_uri: data.post_logout_redirect_uri,
        scope: data.scope,
        grant_types: data.grant_types,
        client_name: data.client_name,
        logo_uri: data.logo_uri
      }, (err, response) => {
        if (err) {
          console.log('Error : ', err);
          res.send(err)
        }
        setting.reg = req.body
        setting.oxd_id = response.data.oxd_id
        fs.writeFileSync("./setting.json", JSON.stringify(setting));
        res.status(200).send({'status':'OK'})
      });
})

app.post('/getAuthURL', (req, res) => {
    data = req.body
    oxd.get_authorization_url({
        oxd_id: data.oxd_id
    }, (err, response) => {
        if (err) {
            console.log('Error : ', err)
            res.send(err)
        }
        res.status(200).send(response)
    });

})

app.post('/logout', (req, res) => {
    let sess = req.session.oxdapi
    if(sess){
        oxd.get_logout_uri({
            oxd_id: setting.oxd_id
        }, (err, response) => {
            if (err) {
                console.log('signOut Error : ', err);
                res.status(200).send({ "error": err })
            }

            req.session.destroy(function(err) {
                res.send(response.data)
            })
        });
    }
    
})


app.listen(setting.client_port);
console.log(`iaam-client running on port ${setting.client_port}`)