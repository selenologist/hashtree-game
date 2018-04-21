Object.filter = (obj, pred) ->
    result = []
    for k, v of obj
        p = pred(v, k)
        if p then result.push(v)
    result

encodeJson = (data) ->
    JSON.stringify(data)

decodeJson = (data) ->
    JSON.parse(data)

encodeMsgpack = (data) ->
    msgpack.encode(data)

decodeMsgpack = (data) ->
    msgpack.decode(data)

decodeB64 = (data) ->
    str = window.atob(data.replace(/_/g, '/').replace(/-/g, '+'))
    arr = new Uint8Array(str.length)
    for i in [0..str.length]
        arr[i] = str.charCodeAt(i)
    arr

encodeB64 = (data) ->
    str = String.fromCharCode.apply(null, data)
    window.btoa(str).replace(/\//g, '_').replace(/\+/g, '-')

encodePubkey = (key) ->
    encodeB64(key).substring(0, 43)
decodePubkey = (key) ->
    decodeB64(key)

encodeSecret = (key) ->
    encodeB64(key).substring(0, 86)
decodeSecret = (key) ->
    decodeB64(key)

encodeKeypair = (pubkey, secret) ->
    j =
        'public': encodePubkey pubkey
        'secret': encodeSecret secret
    encodeJson(j)

decodeKeypair = (encoded) ->
    j = decodeJson(encoded)
    pair = {}
    pair.pubkey = decodePubkey(j.public)
    pair.secret = decodeSecret(j.secret)
    pair


verify = (signed) ->
    pubkey = decodeB64(signed.user)
    message = nacl.sign.open(new Uint8Array(signed.data), pubkey)
    if message?
        decodeMsgpack message
    else
        null

sign = (keypair, data) ->
    data = encodeMsgpack data
    signed =
        "user": encodePubkey keypair.pubkey
        "data": Array.from(nacl.sign(data, keypair.secret))
    console.log(signed)
    signed

client = ->
    ws = new WebSocket('ws://127.0.0.1:3001', 'selenologist-hash-rpg')
    #ws.binaryType = 'arraybuffer'

    user_key = do ->
        user_key = window.localStorage["user_key"]
        if not user_key?
            kp = nacl.sign.keyPair()
            user_key = encodeKeypair(kp.publicKey, kp.secretKey)
            window.localStorage["user_key"] = user_key
        user_key = decodeKeypair(user_key)
        user_key

    dump_loop = (payload) ->
        console.log('dump_loop', payload)
        dump_loop

    get_tile_collection = (latest) ->
        req = new XMLHttpRequest()
        req.responseType = "arraybuffer"
        req.addEventListener("load", ->
            console.log('resp', this)
            u8 = new Uint8Array(this.response)
            signed = decodeMsgpack u8
            signed =
                user: signed[0]
                data: signed[1]
            list = verify(signed)
            e = document.getElementsByTagName('body')[0]
            if list
                e.insertAdjacentHTML('beforeend', '<pre class="ok">' + encodeJson(list) + '</pre>')
            else
                e.insertAdjacentHTML('beforeend', '<pre class="err">err</pre>')
        )
        loc = window.location
        base_url = loc.protocol + "//" + loc.host + "/"
        url = base_url + "blocks/" + latest
        console.log("url", url)
        req.open('GET', url)
        req.send()

    get_latest_tiles = (response) ->
        latest = response.Latest
        if latest?
            display_latest_tiles(latest, "ok")
            get_tile_collection(latest)
        else
            display_latest_tiles("Err", "err")
        dump_loop
    
    check_auth = (authresponse) ->
        if authresponse == "AuthOk"
            set_userkey_class("ok")
            send Map: TileLibrary: ["main", "Latest"]
            get_latest_tiles
        else
            set_userkey_class("err")
            dump_loop

    get_server_auth = (signed) ->
        challenge = verify(signed)
        if challenge?
            display_serverkey signed.user
            response = sign(user_key, challenge)
            display_userkey response.user
            send response
            check_auth
        else
            dump_loop

    buf2hex = (buf) ->
      Array.prototype.map.call(
        new Uint8Array(buf),
        (x) => ('00' + x.toString(16)).slice(-2)).join('')

    send = (obj) ->
        console.log 'client sendobj', obj
        pack = encodeJson(obj)
        ws.send pack
    window.send = send

    ws.onopen = (e) ->
        console.log 'client opened', e

    ws.onerror = (e) ->
        console.log 'client error', e

    display_rawmsg = (m) ->
        document.getElementById('rawmsg')
                .innerText = m
    display_serverkey = (k) ->
        e = document.getElementById('serverkey')
        e.innerText = k
        e.className = "ok"
    display_userkey = (k) ->
        document.getElementById('userkey')
                .innerText = k
    set_userkey_class= (c) ->
        document.getElementById('userkey')
                .className = c
    display_latest_tiles = (t, c) ->
        e = document.getElementById('latesttiles')
        e.innerText = t
        e.className = c

    next = get_server_auth
    ws.onmessage = (e) ->
        display_rawmsg e.data
        payload = decodeJson e.data

        next = next(payload)

reloader = ->
    ws = new WebSocket('ws://127.0.0.1:3002', 'selenologist-minimal-reloader')
    
    reload = ->
        location.reload(true)
    
    ws.onmessage = (e) ->
        if e.data == "Reload"
            reload()
        # yup that's it

window.main = ->
    if !(window.File && window.FileReader && window.FileList && window.Blob)
        alert("Not all file APIs available")
    client()
    reloader()
