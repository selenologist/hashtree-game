Object.filter = (obj, pred) ->
    result = []
    for k, v of obj
        p = pred(v, k)
        if p then result.push(v)
    result

encode = (data) ->
    JSON.stringify(data)

decode = (data) ->
    JSON.parse(data)

client = ->
    ws = new WebSocket('ws://127.0.0.1:3001', 'selenologist-hash-rpg')
    #ws.binaryType = 'arraybuffer'

    dump_loop = (payload) ->
        console.log('dump_loop', payload)
        dump_loop

    get_server_auth = (challenge) ->
        console.log('server_auth', challenge)
        dump_loop

    buf2hex = (buf) ->
      Array.prototype.map.call(
        new Uint8Array(buf),
        (x) => ('00' + x.toString(16)).slice(-2)).join('')

    send = (obj) ->
        console.log 'client sendobj', obj
        pack = encode(obj)
        ws.send pack
    window.send = send

    ws.onopen = (e) ->
        console.log 'client opened', e

    ws.onerror = (e) ->
        console.log 'client error', e

    rawmsg = document.getElementById('rawmsg')
    set_rawmsg = (m) -> rawmsg.innerText = m

    next = get_server_auth
    ws.onmessage = (e) ->
        set_rawmsg e.data
        payload = decode e.data

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
    client()
    reloader()
