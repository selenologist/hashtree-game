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
        signed = decode.Msgpack(u8).unwrap()
        list = verify.Signed(signed).unwrap()
        library = addDebugText "Tile Library"
        if list
            library.set encode.Json(list).unwrap(), 'ok'
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
    ws.binaryType = 'arraybuffer'

    window.user_key = do ->
        user_key = window.localStorage["user_key"]
        if not user_key?
            kp = nacl.sign.keyPair()
            user_key = encode.KeypairJson(kp.publicKey, kp.secretKey).unwrap()
            window.localStorage["user_key"] = user_key
        user_key = decode.KeypairJson(user_key).unwrap()

    dump_loop = (payload) ->
        console.log('dump_loop', payload)
        dump_loop

    get_latest_tiles = (response) ->
        dbg_state.set("get_latest_tiles", 'ok')
        latest = response.Result[0]
        if latest?
            window.latest = latest
            dbg_latest_tiles.set latest, "ok"
            get_tile_collection(latest)
        else
            dbg_latest_tiles.set 'Err', 'err'
        
        dbg_state.set("main", 'ok')
        next_msg[0] = dump_loop
    
    check_auth = (authresponse) ->
        dbg_state.set("check_auth", 'ok')
        if authresponse.Auth == "Ok"
            dbg_user_key.set(encode.PubkeyB64(user_key.pubkey).unwrap(), 'ok')
            get_latest =
                Cmd: 'Map'
                Obj: 'TileLibrary'
                Req: ["main", Req: "Latest"]
            send get_latest
            dbg_state.set("get_latest_tiles", 'wait')
            next_msg[0] = get_latest_tiles
        else
            dbg_user_key.set(encode.PubkeyB64(user_key.pubkey).unwrap(), 'err')
            
            dbg_state.set("check_auth", 'err')
            next_msg[0] = dump_loop

    get_server_auth = (signed) ->
        dbg_state.set("get_server_auth", 'ok')
        challenge = verify.Signed(signed).unwrap()
        if challenge?
            dbg_server_key.set encode.PubkeyB64(signed.user).unwrap(), 'ok'
            
            response = sign.Signed(user_key, challenge).unwrap()
            send response
            
            dbg_state.set("check_auth", 'wait')
            next_msg[0] = check_auth
        else
            dbg_state.set("get_server_auth", 'err')
            next_msg[0] = dump_loop

    send = (obj) ->
        console.log 'client sendobj', obj
        pack = encode.Msgpack(obj).unwrap()
        ws.send pack
    window.send = send

    ws.onopen = (e) ->
        console.log 'client opened', e

    ws.onerror = (e) ->
        console.log 'client error', e

    last_msg = document.getElementById('last_msg')
    
    next_msg = [get_server_auth]
    ws.onmessage = (e) ->
        payload = decode.Msgpack(e.data).unwrap()
        console.log('payload', payload)
        last_msg.innerText = JSON.stringify(payload, null, 2) # pretty print with spacing of 2

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
                        signed = sign.Signed(user_key, update).unwrap()
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
    window.dbg_state        = addDebugText 'State'
    window.dbg_server_key   = addDebugText 'Server Pubkey'
    window.dbg_user_key     = addDebugText 'User Pubkey'
    window.dbg_latest_tiles = addDebugText 'Latest Tiles'

    dbg_state.set("get_server_auth", 'wait')
    
    if !(window.File && window.FileReader && window.FileList && window.Blob)
        alert("Not all file APIs available")
    client()
    
    dbg_user_key.set(encode.PubkeyB64(user_key.pubkey).unwrap(), 'wait')
    
    attachUploader()

