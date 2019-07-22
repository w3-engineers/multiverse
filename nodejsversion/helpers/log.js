class Logger {

    constructor(debug = true) {
        this._debug = debug;
        // if(type===this.verbose){
        //     this.v(str);
        // }else if(type===this.debug){
        //     this.d(str);
        // }

    }

    _l(str) {
        console.log(this._tag + ":: " + str);
    }

    v(str, tag = "INFO") {
        this._tag = tag;
        this._l(str);
    }

    d(str, tag = "DEBUG") {
        if (this._debug) {
            this._tag = tag;
            this._l(str);
        }
    }
}

module.exports = {Logger};