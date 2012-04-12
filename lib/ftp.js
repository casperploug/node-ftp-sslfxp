var net       = require('net'),
    tls       = require('tls'),
    starttls  = require('./starttls');
var util      = require('util');

module.exports = function ftp(options) {
  var root = this;
  if (!options) {
    options = {host: undefined, port: undefined, username: undefined, password: undefined};
  }
  // properties
  this.name = (options.name) ? options.name : 'New FTP';
  this.host = (options.host) ? options.host : '127.0.0.1';
  this.port = (options.port) ? options.port : 21;
  this.username = (options.username) ? options.username : 'Anonymous';
  this.password = (options.password) ? options.password : '';

  this.buffering = false;
  this.res_buffer = '';
  this._excess_buffer = '';

  this.unencrypted = {write: false};
  this.encrypted = {write: false};

  // events
  this.onestablished = function() {};
  this.onssl = function() {};
  this.onloggedin  = function() {};
  this.ondir = function() {};
  this.read_callback = []; // buffering response

  // internal functions
  this._read_unencrypted = function(data) {
    var ftp_data = root.parse_data(data);
    for (var i = 0, j = ftp_data.length; i < j; i++) {
      switch (ftp_data[i].code) {
        case 220:
          root.say('WLCM '+ftp_data[i].msg);
          this.write('AUTH TLS\n');
          break;
        case 234:
          var me = this;
          starttls(root.unencrypted, undefined, function(safe) {
            root.encrypted = safe;
            root.onssl();
            safe.on('data', root._read_encrypted);
            root.encrypted.write('USER '+root.username+'\n');
          });
          break;
        case 530:
          root.say('ERR: '+ftp_data[i].msg);
          break;
        default:
          root.say('UNKN (unencrypted): '+ftp_data[i].code+': '+ftp_data[i].msg);
      }
    }
  };

  this._read_encrypted = function(data) {
    var input;
    if (root.read_callback.length > 0) { root.buffering = true; }
    if (root._excess_buffer.length > 0) { console.log('appending!'); data = root._excess_buffer + data.toString(); }
    root._excess_buffer = '';
    if (root.buffering) {
      root.res_buffer += data.toString();
      var eoo = root.res_buffer.match(/(^[0-9]{3}[ ][^\r\n]+([\s\S]+)?|([\s\S]+?)[\r\n]?[0-9]{3}[ ][^\r\n]+([\s\S]+)?)/);
      if (!eoo) {
        return;
      } else {
        root.res_buffer = (eoo[1]) ? eoo[1] : eoo[3];
        root._excess_buffer = (eoo[1] && !eoo[2]) ? '' : eoo[4];
        root.buffering = false;
      }
    } else { root.res_buffer = ''; }
    if (!root.buffering && root.res_buffer.length > 0) {
      input = root.res_buffer;
    } else if (!root.buffering && root.res_buffer.length === 0) { input = data.toString(); } else { return; }
    var ftp_data = root.parse_data(input);
    if (root.read_callback[0] && !root.buffering) {
      var callback = root.read_callback[0];
      root.read_callback = root.read_callback.slice(1);
      root.res_buffer = '';
      callback(ftp_data);
    } else {
      for (var i = 0, j = ftp_data.length; i < j; i++) {
        switch (ftp_data[i].code) {
          case 1: // dirlist
            root.ondir(ftp_data[i].dirinfo);
            break;
          case 200:
            root.say('CMD '+ftp_data[i].msg); break;
          case 213: break;
          case 230:
            root.say('WLCM '+ftp_data[i].msg); if (ftp_data[i].msg.match(/logged in/i)) { root.onloggedin(true); }; break;
          case 257:
            root.say('PWD '+ftp_data[i].msg); break;
          case 331:
            this.write('PASS '+root.password+'\n'); break;
          case 421:
            root.say('QUIT '+ftp_data[i].msg); break;
          case 503:
            this.write('USER '+root.username+'\n'); break;
          case 530:
            root.say('USPW bad username/password combination');
            root.close();
          default:
            root.say('UNKN '+ftp_data[i].code+': '+ftp_data[i].msg);
        }
      }
    }
  };

  // public functions
  this.say = function(text) {
    var log_line = '[';
    log_line += (this.name.length > 8) ? this.name.substring(0, 7) : this.name;
    while (log_line.length < 9) {
      log_line += ' ';
    }
    log_line += '] ' + text;
    console.log(log_line);
  };

  this.connect = function(obj) {
    if (obj) {
      if (toString.call(obj.onssl) === '[object Function]') { this.onssl = obj.onssl; }
      if (toString.call(obj.onloggedin) === '[object Function]') { this.onloggedin = obj.onloggedin; }
      if (toString.call(obj.ondir) === '[object Function]') { this.ondir = obj.ondir; }
      if (toString.call(obj.onestablished) === '[object Function]') { this.onestablished = obj.onestablished; }
    }
    this.unencrypted = new net.Socket();
    this.unencrypted.connect(this.port, this.host, function() {
      root.onestablished();
    });
    this.unencrypted.on('data', this._read_unencrypted);
  };

  this.close = function() {
    if (this.encrypted.write) {
      this.encrypted.write('QUIT\n');
    } else if (this.unencrypted.write) {
      this.unencrypted.write('QUIT\n');
    }
  };

  this.parse_data = function(data) {
    var lines = data.toString('utf-8').split('\r\n');
    var line_objs = [];
    for (var i = 0, j = lines.length; i < j; i++) {
      var ftp_line_m = lines[i].match(/^([0-9]{3})(\-| )(.+)$/);
      if (!ftp_line_m) {
        var dir_line_m = lines[i].match(/^[drwx-]{10}[ ]+([0-9]+) ([^ ]+)[ ]+([^ ]+)[ ]+([0-9]+) ([A-Z][a-z]{2} [ 0-9]{2} [ :0-9]{5}) (.+)$/);
        if (dir_line_m)
          line_objs.push({code: 1, eol: false, msg: dir_line_m[0], dirinfo: { count: (parseInt(dir_line_m[1]) > 2) ? parseInt(dir_line_m[1]) - 2 : 0, user: dir_line_m[2], group: dir_line_m[3], size: parseInt(dir_line_m[4]), date: new Date(dir_line_m[5]), name: dir_line_m[6]}});
        else
          continue;
      } else
        line_objs.push({code: parseInt(ftp_line_m[1]), eol: (ftp_line_m[1] === '-') ? false : true, msg: ftp_line_m[3]});
    }
    return line_objs;
  };

  this.write_encrypted = function(data, buffering) {
    this.buffering = (!!buffering) ? buffering : false;
    if (this.encrypted.write) {
      if (!data.match(/\n$/)) { data += '\n'; }
      this.encrypted.write(data);
    } else { return false; }
  };

  this.cmd = function(text, callback) {
    var ticks = 0; while (ticks < 100) { ticks++; } // hack
    if (root.encrypted.write) {
      if (root.encrypted._pendingBytes > 0) { console.log('UNABLE TO ISSUE CMD '+text); return; };
      if (toString.call(callback) === '[object Function]') {
        root.read_callback.push(callback);
      }
      root.write_encrypted(text, true, callback);
    } else if (root.unencrypted.write) {

    }
  };
};