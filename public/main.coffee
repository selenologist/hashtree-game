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
    loc = window.location
    base_url = loc.protocol + "//" + loc.host + "/"
    blocks_url = base_url + "blocks/"
    req = new XMLHttpRequest()
    req.responseType = "arraybuffer"
    req.addEventListener("load", ->
        u8 = new Uint8Array(this.response)
        signed = decode.Msgpack(u8).unwrap()
        list = verify.Signed(signed).unwrap()
        library = addDebugText "Tile Library"
       
        tile_library = document.getElementById('tile_library')
        while tile_library.firstChild # remove all existing displayed tiles
            tile_library.removeChild(tile_library.firstChild)

        add_tile = (name, hash) ->
            icon = document.createElement('div')
            icon.className = 'icon'
            img = document.createElement('img')
            img.src = blocks_url + hash
            tt = document.createElement('tt')
            tt.innerText = name
            icon.insertAdjacentElement('beforeend', img)
            icon.insertAdjacentElement('beforeend', tt)
            tile_library.insertAdjacentElement('beforeend', icon)

        if list
            library.set encode.Json(list.value).unwrap(), 'ok'
            for name, hash of list.value[0]
                add_tile name, hash
        else
            library.set 'Err', 'err'
    )
    url = blocks_url + latest
    req.open('GET', url)
    req.send()

window.getUnixTime = ->
    Math.floor((new Date()).getTime() / 1000)

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

    check_update_result = (vr) ->
        next_msg[0] = dump_loop
        if vr.Response? && vr.Response == "VerifierResult"
            res = proto.VerifierResult vr.Result
            if res.is_ok()
                dbg_state.set("check_update_result update good", 'ok')
                window.latest = res.inner[0]
                get_tile_collection(window.latest)
            else
                dbg_state.set("check_update_result bad result", 'err')
        else
            dbg_state.set("check_update_result wrong message", 'err')

    check_upload_result = (f, result) ->
        if result.Response? && result.Response == 'Ok'
            hash = result.Result
            f.debug.set hash, 'ok'
            update = proto.UpdateNamedHash(f.name, hash, window.latest)
            signed = sign.Signed(user_key, update).unwrap()
            send proto.TileLibrary 'main',
                Req: 'Update'
                user: signed.user
                data: signed.data
            dbg_state.set("check_update_result", 'wait')
            next_msg[0] = check_update_result
        else
            f.debug.set result, 'err'
            next_msg[0] = dump_loop

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
            get_latest = proto.TileLibrary "main", Req: "Latest"
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
            f = {}
            f.debug = addDebugText 'File Upload'
            f.debug.set files[0].name, 'wait'
            f.name = files[0].name.replace(/\..*/, '') # strip extension
            reader = new FileReader()
            reader.onloadend = (file) ->
                array = new Uint8Array(this.result)
                array = Array.from(array)
                command = proto.UploadRaw array
                send command
                dbg_state.set("check_upload_result", 'wait')
                next_msg[0] = (msg) -> check_upload_result(f, msg)
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

