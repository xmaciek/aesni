// MIT License
//
// Copyright (c) Maciej Latocha ( latocha.maciek@gmail.com )
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "aesni.hpp"

int main( [[maybe_unused]] int argc, [[maybe_unused]] char** argv )
{
    auto veryLongText = "A very long plain text to show AES256 encryption via sse and aes-ni intrinsics";
    int len = std::strlen( veryLongText );

    // create and fill aligned buffer for source data
    std::vector<__m128i> src( ( len + 15 ) / 16 );
    auto paddingBegin = std::copy_n( veryLongText, len, reinterpret_cast<char*>( src.data() ) );

    // fill remaining padding bytes, you can do with random (ie ignore), 0, or standards ANSI_X9_23, PKCS_5_7, ISO_IEC_7816_4
    unsigned int paddingSize = 16 * src.size() - len;
    std::generate_n( (unsigned char*)paddingBegin, paddingSize, aesni::padding::ANSI_X9_23{ paddingSize } );


    // WARN: dont keep your passwords/keys as plain text or plain variable in binary or heap,
    // make it obfuscated and deobfuscate on a stack on demand, then overwrite stack after you are done with [de,en]cryption.
    // Consider the following key and iv as pair of keys used for operation modes example.
    __m128i keySSE; std::memcpy( &keySSE, "LazyFoxJumpsOver", 16 );
    __m128i ivSSE; std::memcpy( &ivSSE, "VerySudoRandomIV", 16 );
    std::vector<__m128i> encrypted( src.size() );
    std::vector<__m128i> decrypted( src.size() );


    auto printSSE = []( __m128i it )
    {
        uint8_t x[ 16 ];
        std::memcpy( x, &it, 16 );
        std::printf( "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX ",
            x[ 0 ], x[ 1 ], x[ 2 ],  x[ 3 ],  x[ 4 ],  x[ 5 ],  x[ 6 ],  x[ 7 ],
            x[ 8 ], x[ 8 ], x[ 10 ], x[ 11 ], x[ 12 ], x[ 13 ], x[ 14 ], x[ 15 ]
        );
    };
    auto testCipher = [&src, printSSE]( const auto& encrypted, const auto& decrypted, auto text )
    {
        std::printf( "\nencrypted AES256-%s:\t", text ); for ( auto&& it : encrypted ) printSSE( it );
        std::printf( "\ndecrypted AES256-%s:\t", text ); for ( auto&& it : decrypted ) printSSE( it );
        bool success = std::memcmp( src.data(), decrypted.data(), src.size() * 16 ) == 0;
        if ( success ) std::printf( "\ndecrypted as text:\t%s", (const char*)decrypted.data() );
        std::printf( "\nstatus AES256-%s:\t%s\n", text, success ? "OK" : "FAIL" );
    };
    std::printf( "passwd:\t\t\t" ); printSSE( keySSE );
    std::printf( "\niv:\t\t\t" ); printSSE( ivSSE );
    std::printf( "\ninput text:\t\t%s", veryLongText );
    std::printf( "\ninput text as blocks:\t" ); for ( auto&& it : src ) printSSE( it );
    std::printf( "\n" );



    std::transform( src.begin(),       src.end(),       encrypted.begin(), aesni::Encryptor256ECB{ keySSE } );
    std::transform( encrypted.begin(), encrypted.end(), decrypted.begin(), aesni::Decryptor256ECB{ keySSE } );
    testCipher( encrypted, decrypted, "ECB" );

    std::transform( src.begin(),       src.end(),       encrypted.begin(), aesni::Encryptor256CBC{ keySSE, ivSSE } );
    std::transform( encrypted.begin(), encrypted.end(), decrypted.begin(), aesni::Decryptor256CBC{ keySSE, ivSSE } );
    testCipher( encrypted, decrypted, "CBC" );

    std::transform( src.begin(),       src.end(),       encrypted.begin(), aesni::Encryptor256CFB{ keySSE, ivSSE } );
    std::transform( encrypted.begin(), encrypted.end(), decrypted.begin(), aesni::Decryptor256CFB{ keySSE, ivSSE } );
    testCipher( encrypted, decrypted, "CFB" );

    std::transform( src.begin(),       src.end(),       encrypted.begin(), aesni::Encryptor256OFB{ keySSE, ivSSE } );
    std::transform( encrypted.begin(), encrypted.end(), decrypted.begin(), aesni::Decryptor256OFB{ keySSE, ivSSE } );
    testCipher( encrypted, decrypted, "OFB" );

    return 0;
}
