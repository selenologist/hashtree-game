window.reloader = ->
    ws = new WebSocket('ws://127.0.0.1:3002', 'selenologist-minimal-reloader')
    
    reload = ->
        location.reload(true)
    
    ws.onmessage = (e) ->
        if e.data == "Reload"
            reload()
        # yup that's it
