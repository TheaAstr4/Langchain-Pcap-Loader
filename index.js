const pcapParser = require('./build/Release/pcap_parser');

function parsePcap(filePath) {
    return pcapParser.parsePcap(filePath);
}

module.exports = { parsePcap };
