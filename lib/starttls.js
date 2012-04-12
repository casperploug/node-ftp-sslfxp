/* 
 * based on https://gist.github.com/942466
 * slightly modified removeEvents bug, and modified callback arg
 */
module.exports = function starttls(socket, options, cb) {

  var sslcontext = require('crypto').createCredentials(options);

  var pair = require('tls').createSecurePair(sslcontext, false);

  var cleartext = pipe(pair, socket);

  pair.on('secure', function() {
    var verifyError = pair.ssl.verifyError();

    if (verifyError) {
      cleartext.authorized = false;
      cleartext.authorizationError = verifyError;
    } else {
      cleartext.authorized = true;
    }
    if (cb) cb(cleartext);
  });

  cleartext._controlReleased = true;
  return cleartext;
};

function forwardEvents(events,emitterSource,emitterDestination) {
  var map = {}
  for(var i = 0; i < events.length; i++) {
    var name = events[i];
    var handler = (function generateForwardEvent(){
       return function forwardEvent(name) {
          return emitterDestination.emit.apply(emitterDestination,arguments)
       }
    })(name);
    map[name] = handler;
    emitterSource.on(name,handler);
  }
  return map;
}
function removeEvents(map,emitterSource) {
   for(var k in map) {
      emitterSource.removeListener(k,map[k])
   }
}

function pipe(pair, socket) {
  pair.encrypted.pipe(socket);
  socket.pipe(pair.encrypted);

  pair.fd = socket.fd;
  var cleartext = pair.cleartext;
  cleartext.socket = socket;
  cleartext.encrypted = pair.encrypted;
  cleartext.authorized = false;

  function onerror(e) {
    if (cleartext._controlReleased) {
      cleartext.emit('error', e);
    }
  }

  var map = forwardEvents(["timeout","end","close"],socket,cleartext);
  function onclose() {
    socket.removeListener('error', onerror);
    socket.removeListener('close', onclose);
    removeEvents(map,socket)
  }

  socket.on('error', onerror);
  socket.on('close', onclose);

  return cleartext;
}