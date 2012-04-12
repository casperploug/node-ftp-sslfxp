var net       = require('net'),
    tls       = require('tls'),
    starttls  = require('./starttls');

module.exports = function ftp(options) {
  var root = this;
  if (!options) {
    options = {host: undefined, port: undefined, username: undefined, password: undefined};
  }
  this.name = (options.name) ? options.name : 'New FTP';
  this.host = (options.host) ? options.host : '127.0.0.1';
  this.port = (options.port) ? options.port : 21;
  this.username = (options.username) ? options.username : 'Anonymous';
  this.password = (options.password) ? options.password : '';

  this.unencrypted = {write: false};
  this.encrypted = {write: false};

  this.say = function(text) {
    var log_line = '[';
    log_line += (this.name.length > 8) ? this.name.substring(0, 7) : this.name;
    while (log_line.length < 9) {
      log_line += ' ';
    }
    log_line += '] ' + text;
    console.log(log_line);
  };

  this.connect = function() {
    this.unencrypted = new net.Socket();
    this.unencrypted.connect(this.port, this.host, function() {
      root.say('connection established');
    });
    this.unencrypted.on('data', this.read_unencrypted);
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

  this.read_unencrypted = function(data) {
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
            root.say('SSL');
            safe.on('data', root.read_encrypted);
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

  this.read_encrypted = function(data) {
    var ftp_data = root.parse_data(data);
    for (var i = 0, j = ftp_data.length; i < j; i++) {
      switch (ftp_data[i].code) {
        case 1: // dirlist
          root.say('DIR '+ftp_data[i].dirinfo.name+' ('+ftp_data[i].dirinfo.count+')');
          break;
        case 200:
          root.say('CMD '+ftp_data[i].msg); break;
        case 230:
          root.say('WLCM '+ftp_data[i].msg); break;
        case 503:
          this.write('USER '+root.username+'\n');
          break;
        case 331:
          this.write('PASS '+root.password+'\n');
          break;
        default:
          root.say('UNKN '+ftp_data[i].code+': '+ftp_data[i].msg);
      }
    }
  };

  this.write_encrypted = function(data) {
    if (this.encrypted.write) {
      if (!data.match(/\n$/)) { data += '\n'; }
      this.encrypted.write(data);
    } else { return false; }
  };
};