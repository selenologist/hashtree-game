encode =
    Json: (data) ->
        JSON.stringify(data)
    Msgpack: (data) ->
        msgpack.encode(data)
    B64: (data) ->
        str = String.fromCharCode.apply(null, data)
        window.btoa(str).replace(/\//g, '_').replace(/\+/g, '-')
    
    Pubkey: (key) ->
        encode.B64(key).substring(0, 43)
    Secret: (key) ->
        encode.B64(key).substring(0, 86)

    Keypair: (pubkey, secret) ->
        j =
            'public': encode.Pubkey pubkey
            'secret': encode.Secret secret
        encode.Json(j)

decode =
    Json: (data) ->
        JSON.parse(data)

    Msgpack: (data) ->
        msgpack.decode(data)

    B64: (data) ->
        str = window.atob(data.replace(/_/g, '/').replace(/-/g, '+'))
        arr = new Uint8Array(str.length)
        for i in [0..str.length]
            arr[i] = str.charCodeAt(i)
        arr

    Pubkey: (key) ->
        decode.B64(key)

    Secret:(key) ->
        decode.B64(key)

    Keypair: (encoded) ->
        j = decode.Json(encoded)
        pair = {}
        pair.pubkey = decode.Pubkey(j.public)
        pair.secret = decode.Secret(j.secret)
        pair


verify =
    Signed: (signed) ->
        pubkey = decode.B64(signed.user)
        message = nacl.sign.open(new Uint8Array(signed.data), pubkey)
        if message?
            decode.Msgpack message
        else
            null
    Packed: (signed) ->
        s = {
            user: signed[0]
            data: signed[1]
        }
        verify.Signed(s)


sign =
    Signed: (keypair, data) ->
        data = encode.Msgpack data
        signed =
            "user": encode.Pubkey keypair.pubkey
            "data": Array.from(nacl.sign(data, keypair.secret))
        signed
    Packed: (keypair, data) ->
        s = sign.Signed(keypair, data)
        [s.user, s.data]

window.encode = encode
window.decode = decode
window.verify = verify
window.sign   = sign
