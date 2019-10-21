const express = require('express')
const swig = require('swig')
const axios = require('axios')
const discord = require('discord.js')

const jwt = require('jsonwebtoken')
const oauth2 = require('discord-oauth2')
const crypto = require('crypto')

const cookies = require('cookie-parser')
const favicon = require('serve-favicon');
const bodyparser = require('body-parser')

const low = require('lowdb')
const filesync = require('lowdb/adapters/FileSync')

const config = require('./config.json')
const secrets = require('./secrets.json')

const client = new discord.Client()
const oauth = new oauth2()
const app = express()

const adapter = new filesync(__dirname+'/'+config.database)
const db = low(adapter)

app.use(cookies())
app.use(bodyparser.urlencoded({ extended: true }))
app.use('/static', express.static(__dirname+'/static'))
app.use(favicon(__dirname + '/static/favicon.ico'));

app.use((req, res, next) => {
    if (config.debug)
        console.log(`(${req.ip}) ${req.method}${req.originalUrl}`)

    next()
})

db.defaults({users: []}).write()

var secret_key = ''
var acting_guild = null
var licenced_roles = []
var unlicenced_roles = []

// using the swig renderer, compile page templates
const pages = {
    home: swig.compileFile(__dirname+'/pages/index.html'),
    admin: swig.compileFile(__dirname+'/pages/admin.html'),
    error: swig.compileFile(__dirname+'/pages/error.html')
}

// set discord image url size
function set_pfp_size(orig, size) {
    // https://cdn.discordapp.com/avatars/172002275412279296/f5f65755f67ae1dc88d9bb271d0f5bef.png?size=2048
    if (orig.indexOf('?size=') == -1) return orig + '?size=' + size
    else return orig.split('?size=')[0] + '?size=' + size
}

// get url of application
function get_url() {
    return `${config.protocol}://${config.ip}:${config.port}/`
}

// generate secret key
function create_key(length = 32) {
    return new Promise((res, rej) => {
        crypto.randomBytes(length / 2, (err, buff) => {
            var token = buff.toString('hex')
            res(token)
        })
    })
}

// set interval, but calls the function initially
function setIntervalImmediately(func, interval) {
    func()
    return setInterval(func, interval)
}

// using the oauth API, use returned code to get access token
function get_access_token(code) {
    return oauth.tokenRequest({
        code: code,
        client_id: secrets.client_id,
        client_secret: secrets.client_secret,
        grant_type: 'authorization_code',
        redirect_uri: get_url() + 'redirect',
        scope: config.permissions.join(' ')
    })
}

// get user data using access token
function get_user_data(token) {
    return axios.get(config.api + 'users/@me', {
        headers: {'Authorization': `Bearer ${token}`}
    })
}

// build oauth2 url to begin process
function get_oauth2_url() {
    url = 'https://discordapp.com/api/oauth2/authorize'
    url += `?client_id=${secrets.client_id}`
    url += `&redirect_uri=${encodeURIComponent(get_url()+'redirect')}`
    url += `&response_type=code&scope=${config.permissions.join(' ')}`
    return url
}

// web endpoint wrapper that checks auth, returns 401 if not
function auth_endpoint(callback) {
    return (req, res) => {
        var token = req.cookies.session
        jwt.verify(token, secret_key, (err, user) => {
            if (!err && config.admins.indexOf(user.id) != -1) {
                callback(req, res, user)
            } else {
                if (config.debug) {
                    res.status(401).send(pages.error({
                        message: 'Unauthorized',
                        details: err.message,
                        code: 401
                    }))
                } else {
                    res.redirect(get_oauth2_url())
                }
            }
        })
    }
}

// oauth2 redirect endpoint
app.get('/redirect', (req, res) => {
    var code = req.query.code
    var err = req.query.error

    if (err && !config.debug)
        res.redirect('/')

    get_access_token(code).then((resp) => {
        return get_user_data(resp.access_token)
    }).then((resp) => {
        var user_data = resp.data

        if (config.admins.indexOf(user_data.id) != -1) {
            let token = jwt.sign(user_data, secret_key)
            res.cookie('session', token).redirect('/admin')
        } else {
            var find = db.get('users').find({
                id: user_data.id
            }).value()

            if (!find) {
                db.get('users').push({
                    id: user_data.id,
                    licenced: false,
                    notes: ''
                }).write() }
            res.redirect('https://discord.gg/' + config.discord_invite)
        }
    }).catch((err) => {
        if (config.debug) {
            res.status(500).send(pages.error({
                message: 'Internal server error',
                details: err.message,
                code: 500
            }))
        } else {
            res.status(500).send(pages.error({
                message: 'Internal server error',
                code: 500
            }))
        }
    })
})

app.get('/', (req, res) => {
    res.send(pages.home({
        oauth2: get_oauth2_url()
    }))
})

function apply_roles(member, licenced, log=true) {
    var promise = null
    if (licenced) {
        promise = member.addRoles(licenced_roles, 'Given licence through web panel').then((m) => {
            return member.removeRoles(unlicenced_roles, 'Given licence through web panel')
        }).then((m) => {
            if (log)
                console.log(`[WEBPANEL] Licence granted: ${m.user.username}#${m.user.discriminator} (${m.displayName})`)
        })
    } else {
        promise = member.removeRoles(licenced_roles, 'Given licence through web panel').then((m) => {
            return member.addRoles(unlicenced_roles, 'Given licence through web panel')
        }).then((m) => {
            if (log)
                console.log(`[WEBPANEL] Licence revoked: ${m.user.username}#${m.user.discriminator} (${m.displayName})`)
        })
    }
    return promise.catch((err) => {
        if (err.name == 'DiscordAPIError') return
    })
}

function revoke_roles(member) {
    var promise = member.removeRoles(licenced_roles, 'Roles revoked through web panel').then((m) => {
        return member.removeRoles(unlicenced_roles, 'Roles revoked through web panel')
    })
    return promise.catch((err) => {
        if (err.name == 'DiscordAPIError') return
    })
}

app.post('/update', auth_endpoint((req, res, user) => {
    var id = req.body.id
    var licenced = req.body.licenced == 'true'
    var notes = req.body.notes

    var member = acting_guild.members.find(m => m.id == id)
    var promise = apply_roles(member, licenced)

    db.get('users').find({id: id}).assign({
        id: id,
        licenced: licenced,
        notes: notes
    }).write()

    promise.then(() => {    
        res.send('OK')
    }).catch((err) => {
        if (config.debug) {
            res.status(500).send(pages.error({
                message: 'Internal server error',
                details: err.message,
                code: 500
            }))
        } else {
            res.status(500).send(pages.error({
                message: 'Internal server error',
                code: 500
            }))
        }
    })
}))

app.get('/logout', (req, res) => {
	res.clearCookie('session').redirect('/')
})

app.post('/delete', auth_endpoint((req, res, user) => {
    var id = req.body.id

    db.get('users').remove({id: id}).write()

    res.send('OK')
}))

app.post('/update_all', auth_endpoint((req, res, user) => {
    if (req.body.mode == 'apply') {
        console.log(`[WEBPANEL] Applying roles to all server members`)
        db.get('users').value().forEach((u) => {
            var member = acting_guild.members.find(m => m.id == u.id)
            apply_roles(member, u.licenced, log=false).catch((err) => {
                if (config.debug) {
                    res.status(500).send(pages.error({
                        message: 'Internal server error',
                        details: err.message,
                        code: 500
                    }))
                } else {
                    res.status(500).send(pages.error({
                        message: 'Internal server error',
                        code: 500
                    }))
                }
            })
        })
    } else {
        console.log(`[WEBPANEL] Revoking roles from all server members`)
        db.get('users').value().forEach((u) => {
            var member = acting_guild.members.find(m => m.id == u.id)
            revoke_roles(member).catch((err) => {
                if (config.debug) {
                    res.status(500).send(pages.error({
                        message: 'Internal server error',
                        details: err.message,
                        code: 500
                    }))
                } else {
                    res.status(500).send(pages.error({
                        message: 'Internal server error',
                        code: 500
                    }))
                }
            })
        })
    }

    res.send('OK')
}))

app.get('/admin', auth_endpoint((req, res, user) => {
    var db_users = db.get('users').value()
    var all_users = db_users.map((db_entry) => {
        var usr = client.users.find(u => u.id == db_entry.id)
        if (usr) {
            return {
                exists: true,
                id: db_entry.id,
                licenced: db_entry.licenced,
                username: usr.username,
                notes: db_entry.notes,
                discriminator: usr.discriminator,
                avatar: set_pfp_size(usr.displayAvatarURL, 64)
            }
        } else {
            return {
                exists: false,
                id: db_entry.id,
                licenced: db_entry.licenced,
                notes: db_entry.notes
            }
        }
    })

    res.send(pages.admin({
        admin: user,
		users: all_users
    }))
}))
  
var server = app.listen(config.port, () => {
    console.log(`Listening at ${get_url()}`)

    setIntervalImmediately(() => {
        console.log('Refreshing secret key, all sessions will become invalid')
        create_key(length=config.secret_length).then((key) => {
            if (config.debug) secret_key = 'debug_secret_key'
            else secret_key = key
        })
    }, config.session_age * 60 * 1000)
})

function stop_bot() {
    client.destroy()
    server.close()
    process.kill(process.pid)
}

client.on('ready', () => {
    console.log(`Bot logged in as '${client.user.tag}'`)
    console.log(`Invite link: https://discordapp.com/oauth2/authorize?client_id=${client.user.id}&scope=bot&permissions=0`)

    var guilds = client.guilds.map((g) => {return g.name}).join(', ')
    acting_guild = client.guilds.find((g) => g.id == config.acting_guild)

    console.log(`Connected guilds: ${guilds}`)
    console.log(`Acting guild: ${acting_guild.name}`)

    config.licenced_roles.forEach((n) => {
        let role = acting_guild.roles.find((r) => r.name == n)
        if (role) licenced_roles.push(role)
        else {
            console.log(`ERROR: role '${n}' not found in guild '${acting_guild.name}'`)
            stop_bot()
        }
    })

    config.unlicenced_roles.forEach((n) => {
        let role = acting_guild.roles.find((r) => r.name == n)
        if (role) unlicenced_roles.push(role)
        else {
            console.log(`ERROR: role '${n}' not found in guild '${acting_guild.name}'`)
            stop_bot()
        }
    })

    console.log(`Loaded licenced permissions: ${config.licenced_roles.join(', ')}`)
    console.log(`Loaded unlicenced permissions: ${config.unlicenced_roles.join(', ')}`)

    config.required_perms.forEach((p) => {
        if (!acting_guild.me.hasPermission(p)) {
            console.log(`ERROR: bot does not have '${p}' permission in guild '${acting_guild.name}'`)
            stop_bot()
        }
    })

    console.log(`Bot has permissions: ${config.required_perms.join(', ')}`)
})

client.on('message', msg => {
    if (msg.content === 'ping')
        msg.reply('pong')
})

client.login(secrets.bot_token)

if (config.debug)
    console.log('WARNING: Running in debug mode, this is not secure!')