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

// tslint:disable: no-string-literal

var promiseTest = {

    executorSync: function( result ) {
        return function( resolve, reject ) {
            resolve( result );
        };
    },

    executorAsync: function( result, duration ) {
        return function( resolve, reject ) {
            setTimeout( function() { resolve( result ); }, duration );
        };
    },

    executorFailSync: function( reason ) {
        return function( resolve, reject ) {
            reject( reason );
        };
    },

    executorFailAsync: function( reason, duration ) {
        return function( resolve, reject ) {
            setTimeout( function() { reject( reason ); }, duration );
        };
    }
};

QUnit.module( "Promises" );

QUnit.test( "Promise.then synchronous function", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorSync( 4 ) );

    promise.then( function( result ) {
        assert.equal( result, 4 );
        done();
    } );

} );

QUnit.test( "Promise.then async function", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorAsync( 4, 200 ) );

    promise.then( function( result ) {
        assert.equal( result, 4 );
        done();
    } );

} );

QUnit.test( "Promise.then no result", function( assert ) {
    var done = assert.async();
    var ud;

    var promise = new Promise( promiseTest.executorAsync( ud, 200 ) );

    promise.then( function( result ) {
        assert.ok( true );
        done();
    } );

} );

QUnit.test( "Promise.then chaining sync", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorSync( 4 ) )
        .then( function( result ) { return result + 1; } )
        .then( function( result ) { return result + 1; } )
        .then( function( result ) { return result + 1; } )
        .then( function( result ) {
            assert.equal( result, 7 );
            done();
        } );

} );

QUnit.test( "Promise.then chaining async promises", function( assert ) {
    var done = assert.async();
    var executor = function( resolve, reject ) {
        setTimeout( function() { resolve( 4 ); }, 200 );
    };

    var promise = new Promise( executor )
        .then( function( result ) { return new Promise( executor ); } )
        .then( function( result ) { return new Promise( executor ); } )
        .then( function( result ) { return new Promise( executor ); } )
        .then( function( result ) {
            assert.equal( result, 4 );
            done();
        } );

} );

QUnit.test( "Promise.then chaining sync promises", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorSync( 4 ) )
        .then( function( result ) { return new Promise( promiseTest.executorSync( ++result ) ); } )
        .then( function( result ) { return new Promise( promiseTest.executorSync( ++result ) ); } )
        .then( function( result ) { return new Promise( promiseTest.executorSync( ++result ) ); } )
        .then( function( result ) {
            assert.equal( result, 7 );
            done();
        } );

} );

QUnit.test( "Promise.then multiple then sync", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorSync( 4 ) );

    var thenCount = 0;

    promise.then( function( result ) {
        ++thenCount;
        return;
    } );

    promise.then( function( result ) {
        if ( ++thenCount === 2 ) {
            assert.ok( true );
            done();
        }
        return;
    } );
} );

QUnit.test( "Promise.then x 2", function( assert ) {
    var done = assert.async();
    var thenCount = 0;

    var promise = new Promise( promiseTest.executorAsync( 4, 200 ) );

    function thenFunc( result ) {
        if ( ++thenCount === 2 ) {
            assert.ok( true );
            done();
        }
        return;
    }

    promise.then( thenFunc );

    promise.then( thenFunc );

} );

QUnit.test( "Promise.then x 2 - with chaining", function( assert ) {
    var done = assert.async();    /// <summary>
    /// A single promise with then() being called twice.
    /// ThenA returns another promise.
    /// ThenB returns a value.
    /// Verify both Thens and chains are resolved.
    /// </summary>

    var promise = new Promise( promiseTest.executorAsync( 5, 200 ) );

    var total = 0;

    promise.then( //Then A
        function( result ) {
            return new Promise( promiseTest.executorAsync( 6 + result, 200 ) );
        } )
        .then(
            function( result ) {
                total += result;
                // Each then gets 5 from the first promise.  ThenA adds 6 while ThenB adds 7
                // to the total for 23.
                assert.equal( total, ( 5 + 6 ) + ( 5 + 7 ) );
                done();
            } );

    promise.then( //Then B
        function( result ) {
            return 7 + result;
        } )
        .then(
            function( result ) {
                total += result;
            } );
} );

QUnit.test( "Promise.all async", function( assert ) {

    var done = assert.async();

    var p1 = new Promise( promiseTest.executorAsync( 1, 300 ) );
    var p2 = new Promise( promiseTest.executorAsync( 2, 100 ) );
    var p3 = new Promise( promiseTest.executorAsync( 3, 400 ) );

    Promise.all( [p3, p1, p2] ).then(
        function( results ) {
            assert.equal( results[2], 2 );
            done();
        } );

} );

QUnit.test( "Promise.all sync", function( assert ) {

    var done = assert.async();

    var p1 = new Promise( promiseTest.executorSync( 1 ) );
    var p2 = new Promise( promiseTest.executorSync( 2 ) );
    var p3 = new Promise( promiseTest.executorSync( 3 ) );

    Promise.all( [p2, p3, p1] ).then(
        function( results ) {
            assert.equal( results[2], 1 );
            done();
        } );

} );

QUnit.test( "Promise.all non-promise params sync", function( assert ) {

    var done = assert.async();

    var p1 = "abc";
    var p2 = new Promise( promiseTest.executorSync( 2 ) );
    var p3 = 123;

    Promise.all( [p2, p3, p1] ).then(
        function( results ) {
            assert.equal( results[2], "abc" );
            done();
        } );

} );

QUnit.test( "Promise.race sync", function( assert ) {

    var done = assert.async();

    var p1 = new Promise( promiseTest.executorSync( 1 ) );
    var p2 = new Promise( promiseTest.executorSync( 2 ) );
    var p3 = new Promise( promiseTest.executorSync( 3 ) );

    Promise.race( [p2, p3, p1] ).then(
        function( result ) {
            assert.equal( result, 2 );
            done();
        } );

} );

QUnit.test( "Promise.race async", function( assert ) {

    var done = assert.async();

    var p1 = new Promise( promiseTest.executorAsync( 1, 300 ) );
    var p2 = new Promise( promiseTest.executorAsync( 2, 200 ) );
    var p3 = new Promise( promiseTest.executorAsync( 3, 100 ) );

    Promise.race( [p2, p3, p1] ).then(
        function( result ) {
            assert.equal( result, 3 );
            done();
        } );

} );

QUnit.test( "Promise.resolve", function( assert ) {

    var done = assert.async();

    Promise.resolve( 4 ).then(
        function( result ) {
            assert.equal( result, 4 );
            done();
        } );

} );

/// ===== reject ====================================================

QUnit.test( "Promise.catch synchronous function", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorFailSync( 4 ) );

    promise["catch"]( function( reason ) {
        assert.equal( reason, 4 );
        done();
    } );

} );

QUnit.test( "Promise.catch async function", function( assert ) {

    var done = assert.async();

    var promise = new Promise( promiseTest.executorFailAsync( 4, 200 ) );

    promise["catch"]( function( reason ) {
        assert.equal( reason, 4 );
        done();
    } );

} );

QUnit.test( "Promise.catch no reason", function( assert ) {

    var done = assert.async();

    var ud;

    var promise = new Promise( promiseTest.executorFailAsync( ud, 200 ) );

    promise["catch"]( function( reason ) {
        assert.ok( true );
        done();
    } );

} );

QUnit.test( "Promise.catch chaining sync", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorFailSync( 4 ) )["catch"]( function( reason ) { return reason + 1; } )
        .then( function( reason ) {
            assert.equal( reason, 5 );
            done();
        } );

} );

QUnit.test( "Promise.catch chaining async promises", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorFailAsync( 4, 200 ) )["catch"](
        function( reason ) {
            return new Promise( promiseTest.executorFailAsync( 5, 200 ) );
        } )["catch"](
            function( reason ) {
                return new Promise( promiseTest.executorFailAsync( 6, 200 ) );
            } )["catch"](
                function( reason ) {
                    return new Promise( promiseTest.executorFailAsync( 7, 200 ) );
                } )["catch"](
                    function( reason ) {
                        assert.equal( reason, 7 );
                        done();
                    } );

} );

QUnit.test( "Promise.catch chaining sync promises", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorFailSync( 4 ) )["catch"](
        function( reason ) { return new Promise( promiseTest.executorFailSync( ++reason ) ); } )["catch"](
            function( reason ) { return new Promise( promiseTest.executorFailSync( ++reason ) ); } )["catch"](
                function( reason ) { return new Promise( promiseTest.executorFailSync( ++reason ) ); } )["catch"](
                    function( reason ) {
                        assert.equal( reason, 7 );
                        done();
                    } );

} );

QUnit.test( "Promise.catch multiple then sync", function( assert ) {
    var done = assert.async();
    var promise = new Promise( promiseTest.executorFailSync( 4 ) );

    var catchCount = 0;

    promise["catch"]( function( reason ) {
        ++catchCount;
        return;
    } );

    promise["catch"]( function( reason ) {
        if ( ++catchCount === 2 ) {
            assert.ok( true );
            done();
        }
        return;
    } );
} );

QUnit.test( "Promise.catch x 2", function( assert ) {
    var done = assert.async();
    var catchCount = 0;

    var promise = new Promise( promiseTest.executorFailAsync( 4, 200 ) );

    function catchFunc( reason ) {
        if ( ++catchCount === 2 ) {
            assert.ok( true );
            done();
        }
        return;
    }

    promise["catch"]( catchFunc );

    promise["catch"]( catchFunc );

} );

QUnit.test( "Promise.catch x 2 - with chaining", function( assert ) {
    var done = assert.async();    /// <summary>
    /// A single promise with then() being called twice.
    /// ThenA returns another promise.
    /// ThenB returns a value.
    /// Verify both Thens and chains are resolved.
    /// </summary>

    var promise = new Promise( promiseTest.executorFailAsync( 5, 100 ) );

    var total = 0;

    promise["catch"]( //Then A
        function( reason ) {
            return new Promise( promiseTest.executorFailAsync( 6 + reason, 400 ) );
        } )["catch"](
            function( reason ) {
                total += reason;
                // Each then gets 5 from the first promise.  ThenA adds 6 while ThenB adds 7
                // to the total for 23.
                assert.equal( total, ( 5 + 6 ) + ( 5 + 7 ) );
                done();
            } );

    promise["catch"]( //Then B
        function( reason ) {
            return 7 + reason;
        } )
        .then(
            function( reason ) {
                total += reason;
            } );
} );

QUnit.test( "Promise.all fail async", function( assert ) {
    var done = assert.async();
    var p1 = new Promise( promiseTest.executorAsync( 1, 300 ) );
    var p2 = new Promise( promiseTest.executorAsync( 2, 100 ) );
    var p3 = new Promise( promiseTest.executorFailAsync( 3, 400 ) );

    Promise.all( [p3, p1, p2] )["catch"](
        function( reason ) {
            assert.equal( reason, 3 );
            done();
        } );

} );

QUnit.test( "Promise.all fail sync", function( assert ) {
    var done = assert.async();
    var p1 = new Promise( promiseTest.executorSync( 1 ) );
    var p2 = new Promise( promiseTest.executorFailSync( 2 ) );
    var p3 = new Promise( promiseTest.executorSync( 3 ) );

    Promise.all( [p3, p1, p2] )["catch"](
        function( reason ) {
            assert.equal( reason, 2 );
            done();
        } );

} );

QUnit.test( "Promise.race fail sync", function( assert ) {
    var done = assert.async();
    var p1 = new Promise( promiseTest.executorSync( 1 ) );
    var p2 = new Promise( promiseTest.executorFailSync( 2 ) );
    var p3 = new Promise( promiseTest.executorSync( 3 ) );

    Promise.race( [p2, p3, p1] )["catch"](
        function( reason ) {
            assert.equal( reason, 2 );
            done();
        } );

} );

QUnit.test( "Promise.race fail async", function( assert ) {
    var done = assert.async();
    var p1 = Promise.reject( 1 );
    var p2 = new Promise( promiseTest.executorAsync( 2, 200 ) );
    var p3 = new Promise( promiseTest.executorFailAsync( 3, 100 ) );

    Promise.race( [p2, p3, p1] )["catch"](
        function( reason ) {
            assert.equal( reason, 1 );
            done();
        } );

} );

QUnit.test( "Promise.reject", function( assert ) {
    var done = assert.async();
    Promise.reject( 4 )["catch"](
        function( reason ) {
            assert.equal( reason, 4 );
            done();
        } );

} );
