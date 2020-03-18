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

var asn1 = (function() {

    var asn1Types = {
        0x00: "CUSTOM",
        0x01: "BOOLEAN", 0x02: "INTEGER", 0x03: "BIT STRING", 0x04: "OCTET STRING",
        0x05: "NULL", 0x06: "OBJECT IDENTIFIER", 0x10: "SEQUENCE", 0x11: "SET",
        0x13: "PRINTABLE STRING", 0x17: "UTCTime"
    };

    var asn1Classes = {
        0x00: "UNIVERSAL", 0x01: "APPLICATION", 0x02: "Context-Defined", 0x03: "PRIVATE"
    };

    function parse(bytes, force) {

        force = !!force;

        var type = asn1Types[bytes[0] & 0x1F],
            dataLen = bytes[1],
            i = 0,
            constructed = !!(bytes[0] & 0x20),
            //_class = asn1Classes[bytes[0] >>> 6],
            remainder,
            child,
            header;

        if (dataLen & 0x80) { // length > 127
            for (i = 0, dataLen = 0; i < (bytes[1] & 127); i++) {
                dataLen = (dataLen << 8) + bytes[2 + i];
            }
        }

        header = 2 + i;

        if (type === undefined || dataLen > bytes.length) { return null; }

        var obj = constructed ? [] : {};

        obj.type = type;
        obj.header = header;
        //obj.length = dataLen + header;
        obj.data = bytes.slice(0, dataLen + header);
        //obj.class = _class;

        if (constructed || force) {
            if (obj.type === "BIT STRING" && bytes[header] === 0) { i++; }
            remainder = bytes.slice(header, obj.data.length);
            //obj.children = [];
            while (remainder.length > 0) {
                child = parse(remainder);
                if (child === null) { break; }
                //obj.children.push(child);
                obj.push(child);
                remainder = remainder.slice(child.data.length);
            }
        }
        return obj;
    }

    function encode(asn1tree) {

        // Walk a tree and output DER/BER encoded stream
        throw new Error("not implemented");
    }

    function toString(objTree, indent) {

        var output = new Array(indent + 1).join(" ") + objTree.type + " (" + objTree.length + ") " + bytesToHexString(objTree.data).substring(0, 16) + "\n";

        if (!objTree.children) { return output; }

        for (var i = 0; i < objTree.children.length; i++) {
            output += toString(objTree.children[i], indent + 4) + "";
        }

        return output;
    }

    return {
        parse: parse,
        encode: encode,
        toString: function(objTree) {
            return toString(objTree, 0);
        }
    };

})();
