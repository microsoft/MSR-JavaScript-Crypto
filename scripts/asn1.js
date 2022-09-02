//*******************************************************************************
//
//    Copyright 2020 Microsoft
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
//*******************************************************************************

// tslint:disable: no-bitwise

var asn1 = (function () {
    var asn1Types = {
        0x00: "CUSTOM",
        0x01: "BOOLEAN",
        0x02: "INTEGER",
        0x03: "BIT STRING",
        0x04: "OCTET STRING",
        0x05: "NULL",
        0x06: "OBJECT IDENTIFIER",
        0x10: "SEQUENCE",
        0x11: "SET",
        0x13: "PRINTABLE STRING",
        0x17: "UTCTime"
    };

    var asn1Classes = {
        0x00: "UNIVERSAL",
        0x01: "APPLICATION",
        0x02: "Context-Defined",
        0x03: "PRIVATE"
    };

    function parse(bytes, force) {
        force = !!force;

        var type = asn1Types[bytes[0] & 0x1f],
            dataLen = bytes[1],
            i = 0,
            constructed = !!(bytes[0] & 0x20),
            //_class = asn1Classes[bytes[0] >>> 6],
            remainder,
            child,
            header;

        if (dataLen & 0x80) {
            // length > 127
            for (i = 0, dataLen = 0; i < (bytes[1] & 127); i++) {
                dataLen = (dataLen << 8) + bytes[2 + i];
            }
        }

        header = 2 + i;

        if (type === undefined || dataLen > bytes.length) {
            return null;
        }

        var obj = constructed ? [] : {};

        obj.type = type;
        obj.header = header;
        //obj.length = dataLen + header;
        obj.data = bytes.slice(0, dataLen + header);
        //obj.class = _class;

        if (constructed || force) {
            if (obj.type === "BIT STRING" && bytes[header] === 0) {
                i++;
            }
            remainder = bytes.slice(header, obj.data.length);
            //obj.children = [];
            while (remainder.length > 0) {
                child = parse(remainder);
                if (child === null) {
                    break;
                }
                //obj.children.push(child);
                obj.push(child);
                remainder = remainder.slice(child.data.length);
            }
        }
        return obj;
    }

    function encode(node) {
        var INTEGER = 0x02,
            BIT_STRING = 0x03,
            OCTET_STRING = 0x04,
            NULL = 0x05,
            OBJECT_IDENTIFIER = 0x06,
            SEQUENCE = 0x10,

            APPLICATION = 0xA0, //01......
            CONSTRUCTED = 0x20; //..1.....

        if (node.hasOwnProperty("INTEGER")) {
            var val = node.INTEGER;
            if (msrcryptoUtilities.isInteger(val)) val = intToBytes(val);
            if (val[0] & 128) val.unshift(0);
            var result = [INTEGER].concat(encodeLength(val), val);
            return result;
        }

        if (node.hasOwnProperty("OCTET STRING")) {
            var val = node["OCTET STRING"];
            if (!(val instanceof Array)) val = encode(val);
            var result = [OCTET_STRING].concat(encodeLength(val), val);
            return result;
        }

        if (node.hasOwnProperty("BIT STRING")) {
            var val = node["BIT STRING"];
            if (!(val instanceof Array)) val = encode(val);
            val.unshift(0);
            var result = [BIT_STRING].concat(encodeLength(val), val);
            return result;
        }

        if (node.hasOwnProperty("NULL")) {
            return [NULL, 0];
        }

        if (node.hasOwnProperty("OBJECT IDENTIFIER")) {
            var val = encodeOid(node["OBJECT IDENTIFIER"]);
            var result = [OBJECT_IDENTIFIER].concat(encodeLength(val), val);
           return result;
        }

        if (node.hasOwnProperty("SEQUENCE")) {
            var nodes = node.SEQUENCE;
            var val = [];
            for (var i = 0; i < nodes.length; i++) {
                val = val.concat(encode(nodes[i]));
            }
            var result = [SEQUENCE | CONSTRUCTED].concat(encodeLength(val), val);
            return result;
        }

        if (node.hasOwnProperty("APPLICATION")) {
            var nodes = node.APPLICATION;
            var structured = isNaN(parseInt(nodes[0])) ? CONSTRUCTED : 0;
            var tag = node.tag;
            var val = structured ? [] : node.APPLICATION;

            if(structured) {
                for (var i = 0; i < nodes.length; i++) {
                    val = val.concat(encode(nodes[i]));
                }
            } 

            var result = [APPLICATION | structured | tag].concat(encodeLength(val), val);
            
            return result;
        }

        throw new Error("unsupported asn.1 type");
    }

    function encodeLength(bytes) {
        var len = bytes.length;
        if (len <= 127 /*0x80*/) return [len];
        var result = intToBytes(len);
        result.unshift(result.length | 128);
        return result;
    }

    function intToBytes(int) {
        var result = [];
        if(int === 0) return [0];
        while (int > 0) {
            result.unshift(int & 255);
            int >>>= 8;
        }
        return result;
    }

    function encodeOid(text) {
        // part-0 and part-1 are encoded in the first byte
        var parts = text.split(".");
        var result = [parseInt(parts[0] * 40 + parseInt(parts[1]))];

        // the remaining parts are encoded as base-128 with bit 7=1 except for the last byte
        for (var i = 2; i < parts.length; i++) {
            var val = parseInt(parts[i]);

            var bytes = [];
            while (val > 0) {
                bytes.push((val & 127) | 128);
                val = val >>> 7;
            }
            bytes[0] = bytes[0] & 127;

            result = result.concat(bytes.reverse());
        }
        return result;
    }

    
    function toString(objTree, indent) {
        var output =
            new Array(indent + 1).join(" ") +
            objTree.type +
            " (" +
            objTree.length +
            ") " +
            bytesToHexString(objTree.data).substring(0, 16) +
            "\n";

        if (!objTree.children) {
            return output;
        }

        for (var i = 0; i < objTree.children.length; i++) {
            output += toString(objTree.children[i], indent + 4) + "";
        }

        return output;
    }


    return {
        parse: parse,
        encode: encode,
        toString: function (objTree) {
            return toString(objTree, 0);
        }
    };
})();
