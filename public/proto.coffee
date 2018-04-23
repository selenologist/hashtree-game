class encode
    @Json: (data) ->
        try
            Ok(JSON.stringify(data))
        catch
            Err("Failed to encode JSON")

    @Msgpack: (data) ->
        try
            Ok(msgpack.encode(data))
        catch
            Err("Failed to encode MessagePack")

    @B64: (data) ->
        try # seems window.btoa can't fail but try/catch anyway
            str = String.fromCharCode.apply(null, data)
            Ok(window.btoa(str).replace(/\//g, '_').replace(/\+/g, '-'))
        catch
            Err("Failed to encode base64")
    
    @PubkeyB64: (key) ->
        try
            Ok(encode.B64(key)
                  .unwrap()
                  .substring(0, 43)) #ceil(256 bits of key/6 bits per char)
        catch e
            Err(e)
    @SecretB64: (key) ->
        try
            Ok(encode.B64(key)
                  .unwrap()
                  .substring(0, 86)) #ceil(512 bits of key/6 bits per char)
        catch e
            Err(e)

    @KeypairB64: (pubkey, secret) ->
        try
            Ok('public': (encode.PubkeyB64 pubkey).unwrap()
               'secret': (encode.SecretB64 secret).unwrap())
        catch e
            Err(e)
    @eypairJson: (pubkey, secret) ->
        try
            obj = KeypairB64(pubkey, secret).unwrap()
            encode.Json(obj)
        catch e
            Err(e)

class decode
    @Json: (data) ->
        try
            Ok(JSON.parse(data))
        catch
            Err("Failed to parse JSON")

    @Msgpack: (data) ->
        try
            if (data instanceof ArrayBuffer)
                data = new Uint8Array(data) # convert to Uint8Array from ArrayBuffer
            Ok(msgpack.decode(data))
        catch
            Err("Failed to parse MessagePack")

    @B64: (data) ->
        try
            str = window.atob(data.replace(/_/g, '/').replace(/-/g, '+'))
            arr = new Uint8Array(str.length)
            for i in [0..str.length]
                arr[i] = str.charCodeAt(i)
            Ok(arr)
        catch
            Err("Failed to parse base64")

    @PubkeyB64: (key) ->
        decode.B64(key)

    @SecretB64:(key) ->
        decode.B64(key)

    @KeypairB64: (obj) ->
        pubkey = decode.PubkeyB64(obj.public)
        pubkey.and_then ->
            secret = decode.SecretB64(obj.secret)
            secret.and_then ->
                pair =
                    pubkey: pubkey.unwrap() # safe at this point
                    secret: secret.unwrap()
                Ok(pair)
    @KeypairJson: (encoded) ->
        (decode.Json encoded).and_then (obj) ->
            decode.KeypairB64 obj

class verify
    @Signed: (signed) ->
        message = nacl.sign.open(new Uint8Array(signed.data), signed.user)
        if message?
            Ok(decode.Msgpack message)
        else
            Err("Failed to verify Signed")
    @Packed: (signed) ->
        s = {
            user: signed[0]
            data: signed[1]
        }
        verify.Signed(s)


class sign
    @Signed: (keypair, data) ->
        try
            mpack = (encode.Msgpack data).unwrap()
            signed =
                user: Array.from(keypair.pubkey)
                data: Array.from(nacl.sign(mpack, keypair.secret))
            Ok(signed)
        catch e
            Err(e)
    @Packed: (keypair, data) ->
        sign.Signed(keypair, data).and_then (s) ->
            Ok([s.user, s.data])

class proto
    @TileLibrary: (name, req) ->
        Cmd: 'Map'
        Data:
            Obj: 'TileLibrary'
            Req: [name, req]
    @UploadRaw: (array) ->
        Cmd: 'UploadRaw'
        Data: array
    @UpdateNamedHash: (name, hash, latest) ->
        timestamp: [getUnixTime()]
        command:
            Cmd: 'Set'
            Data: [name, hash]
        last: [latest]

    @VerifierResult: (vr) ->
        # fuuucking hell. std::Result will be serialized using an integer variant key.
        # I need a serialization scheme with less friction.
        if vr[0] == 0 # Ok
            Ok(vr[1][0]) # BlockHash
        else # Err
            Err(vr[1][0].Error) # VerifierError

window.encode = encode
window.decode = decode
window.verify = verify
window.sign   = sign
window.proto  = proto
