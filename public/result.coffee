class Result
    constructor: (type, inner, caller) ->
        @type = if type == 'Ok' then 'Ok' else 'Err'
        @inner = inner
        @caller = caller

    toString: () -> # override toString method
        s = @type + '(' + @inner.toString() + ')'
        if @caller?
            s += ' caller: ' + @caller.toString()
        s

    unwrap: -> # if 'Ok' return inner, else throw inner
        if @type == 'Ok'
            @inner
        else
            throw @inner
    and_then: (f) -> # return f(inner) if Ok, else return this
        if @type == 'Ok'
            f(@inner)
        else
            @
    or_else: (f) -> # return inner if Ok, else return f(inner)
        if @type == 'Ok'
            @inner
        else
            f(@inner)

Ok = (inner) ->
    # flattens a Result into itself rather than wrapping
    if (inner instanceof Result)
        inner
    else
        new Result('Ok', inner)

Err = (inner) ->
    if (inner instanceof Result)
        inner
    else
        new Result('Err', inner, Err.caller)

window.Result = Result
window.Ok = Ok
window.Err = Err
