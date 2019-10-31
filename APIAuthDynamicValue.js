var APIAuthDynamicValue = function () {
    this.sha1 = function (str, key) {
        var dv = new DynamicValue('com.luckymarmot.HMACDynamicValue', {
            'input': str,
            'key': key,
            'algorithm': 1 /* SHA1 */
        });
        return dv.getEvaluatedString();
    };
    this.b64 = function (str) {
        var dv = new DynamicValue('com.luckymarmot.Base64EncodingDynamicValue', {
            'input': str,
            'mode': 0 /* Encode */
        });
        return dv.getEvaluatedString();
    };
    this.parseURL = function (href) {
        var match = href.match(/^(https?\:)\/\/(([^:\/?#]*)(?:\:([0-9]+))?)(\/[^?#]*)(?:\?([^#]*|)(#.*|))?$/);
        return match && {
            protocol: match[1],
            host: match[2],
            hostname: match[3],
            port: match[4],
            pathname: match[5],
            search: match[6],
            hash: match[7]
        }
    };
    this.evaluate = function (context) {
        var request = context.getCurrentRequest();
        var uri = this.parseURL(request.url);
        tokens = [];
        tokens.push(uri.pathname);
        if( uri.search !== undefined ) {
            tokens.push(uri.search);
        }
        uri = tokens.join("?");

        var headers = {};
        for (var h in request.headers) {
            headers[h.toLowerCase().trim()] = request.headers[h].trim();
        }

        if (headers['content-type'] === undefined) {
            return "missing Content-Type header";
        }

        if (headers['date'] === undefined) {
            return "missing Date (RFC1123) header";
        }

        if (headers['content-md5'] === undefined) {
            return "missing Content-MD5 header";
        }

        var canonicalArray = [
            request.method.toUpperCase().trim(),
            headers['content-type'],
            headers['content-md5'],
            uri,
            headers['date']
        ];

        console.log(canonicalArray.join(","));

        return 'APIAuth '+this.key+':'+this.sha1(canonicalArray.join(","), this.secret);
    };
    this.title = function (context) {
        return 'API AUTH';
    };
    this.text = function (context) {
        return 'apiauth';
    };
};

APIAuthDynamicValue.identifier = 'com.github.mbordner.PawExtensions.APIAuthDynamicValue';
APIAuthDynamicValue.title = 'API AUTH';
APIAuthDynamicValue.help = 'https://github.com/mbordner/APIAuthDynamicValue';
APIAuthDynamicValue.inputs = [
    DynamicValueInput('key', 'API Key', 'String'),
    DynamicValueInput('secret', 'API Secret', 'SecureValue'),
];

registerDynamicValueClass(APIAuthDynamicValue);