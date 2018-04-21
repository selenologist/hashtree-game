Object.filter = (obj, pred) ->
    result = []
    for k, v of obj
        p = pred(v, k)
        if p then result.push(v)
    result

addDebugText = (label) ->
    row = document.createElement('tr')
    lbl = document.createElement('th')
    lbl.innerText = label
    t = document.createElement('td')
    t.className = 'wait'
    t.innerText = 'wait'
    row.insertAdjacentElement('beforeend', lbl)
    row.insertAdjacentElement('beforeend', t)
    document.getElementById("debug_table")
            .insertAdjacentElement('beforeend', row)
    row.set = (text, status) ->
        t.className = status
        t.innerText = text
    row

get_tile_collection = (latest) ->
    req = new XMLHttpRequest()
    req.responseType = "arraybuffer"
    req.addEventListener("load", ->
        console.log('resp', this)
        u8 = new Uint8Array(this.response)
        signed = decode.Msgpack u8
        list = verify.Packed(signed)
        library = addDebugText "Tile Library"
        if list
            library.set encode.Json(list), 'ok'
        else
            library.set 'Err', 'err'
    )
    loc = window.location
    base_url = loc.protocol + "//" + loc.host + "/"
    url = base_url + "blocks/" + latest
    console.log("url", url)
    req.open('GET', url)
    req.send()

getUnixTime = ->
    Math.round((new Date()).getTime() / 1000)

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

    get_latest_tiles = (response) ->
        latest = response.Latest
        if latest?
            window.latest = latest
            dbg_latest_tiles.set latest, "ok"
            get_tile_collection(latest)
        else
            dbg_latest_tiles.set 'Err', 'err'
        next_msg[0] = dump_loop
    
    check_auth = (authresponse) ->
        if authresponse == "AuthOk"
            dbg_user_key.set(encode.Pubkey(user_key.pubkey), 'ok')
            send Map: TileLibrary: ["main", "Latest"]
            next_msg[0] = get_latest_tiles
        else
            dbg_user_key.set(encode.Pubkey(user_key.pubkey), 'err')
            next_msg[0] = dump_loop

    get_server_auth = (signed) ->
        challenge = verify.Signed(signed)
        if challenge?
            dbg_server_key.set signed.user, 'ok'
            response = sign.Signed(user_key, challenge)
            send response
            next_msg[0] = check_auth
        else
            next_msg[0] = dump_loop

    send = (obj) ->
        console.log 'client sendobj', obj
        pack = encode.Json(obj)
        ws.send pack
    window.send = send

    ws.onopen = (e) ->
        console.log 'client opened', e

    ws.onerror = (e) ->
        console.log 'client error', e

    next_msg = [get_server_auth]
    rawmsg = document.getElementById('rawmsg')
    ws.onmessage = (e) ->
        rawmsg.innerText = e.data
        payload = decode.Json e.data

        next_msg[0](payload)

    window.attachUploader = () ->
        file_select = (evt) ->
            evt.stopPropagation()
            evt.preventDefault()
            files = evt.dataTransfer.files
            for file in files
                console.log('file', file)
            f = addDebugText 'File Upload'
            f.set files[0].name, 'wait'
            reader = new FileReader()
            reader.onloadend = (file) ->
                array = new Uint8Array(this.result)
                array = Array.from(array)
                console.log('array', array)
                command = UploadRaw: array
                console.log('cmd', command)
                send command
                next_msg[0] = (result) ->
                    next_msg[0] = dump_loop
                    if result.UploadOk?
                        hash = result.UploadOk
                        f.set hash, 'ok'
                        update = [
                            getUnixTime(),
                            ["smile", result.UploadOk],
                            window.latest
                        ]
                        signed = sign.Signed(user_key, update)
                        send Map: TileLibrary: ['main', Update: signed]
                    else
                        f.set result, 'err'
            reader.readAsArrayBuffer(files[0])
        handle_drag = (evt) ->
            evt.stopPropagation()
            evt.preventDefault()
            evt.dataTransfer.dropEffect = 'copy'
        upload_zone = document.getElementById('upload_zone')
        upload_zone.addEventListener('drop', file_select, false)
        upload_zone.addEventListener('dragover', handle_drag, false)

window.main = ->
    window.dbg_server_key = addDebugText 'Server Pubkey'
    window.dbg_user_key = addDebugText 'User Pubkey'
    window.dbg_latest_tiles = addDebugText 'Latest Tiles'

    if !(window.File && window.FileReader && window.FileList && window.Blob)
        alert("Not all file APIs available")
    client()
    
    attachUploader()

