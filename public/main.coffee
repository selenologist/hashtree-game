Object.filter = (obj, pred) ->
    result = []
    for k, v of obj
        p = pred(v, k)
        if p then result.push(v)
    result

setText = (id, t, c) ->
    e = document.getElementById(id)
    e.innerText = t
    e.className = c

client = ->
    ws = new WebSocket('ws://127.0.0.1:3001', 'selenologist-hash-rpg')
    #ws.binaryType = 'arraybuffer'

    user_key = do ->
        user_key = window.localStorage["user_key"]
        if not user_key?
            kp = nacl.sign.keyPair()
            user_key = encode.Keypair(kp.publicKey, kp.secretKey)
            window.localStorage["user_key"] = user_key
        user_key = decode.Keypair(user_key)
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
            signed = decode.Msgpack u8
            list = verify.Packed(signed)
            e = document.getElementsByTagName('body')[0]
            if list
                e.insertAdjacentHTML('beforeend', '<pre class="ok">' + encode.Json(list) + '</pre>')
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
            setText 'latesttiles', latest, "ok"
            get_tile_collection(latest)
        else
            setText 'latesttiles', 'Err', 'err'
        dump_loop
    
    check_auth = (authresponse) ->
        if authresponse == "AuthOk"
            setText 'userkey', encode.Pubkey(user_key.pubkey), 'ok'
            send Map: TileLibrary: ["main", "Latest"]
            get_latest_tiles
        else
            setText 'userkey', encode.Pubkey(user_key.pubkey), 'err'
            dump_loop

    get_server_auth = (signed) ->
        challenge = verify.Signed(signed)
        if challenge?
            setText 'serverkey', signed.user, 'ok'
            response = sign.Signed(user_key, challenge)
            send response
            check_auth
        else
            dump_loop

    send = (obj) ->
        console.log 'client sendobj', obj
        pack = encode.Json(obj)
        ws.send pack
    window.send = send

    ws.onopen = (e) ->
        console.log 'client opened', e

    ws.onerror = (e) ->
        console.log 'client error', e

    next = get_server_auth
    ws.onmessage = (e) ->
        setText 'rawmsg', e.data, 'ok'
        payload = decode.Json e.data

        next = next(payload)

window.main = ->
    if !(window.File && window.FileReader && window.FileList && window.Blob)
        alert("Not all file APIs available")
    client()
