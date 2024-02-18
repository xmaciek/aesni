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

#pragma once
#include <wmmintrin.h>

// NOTE TLDR:
// ECB operation mode can be run in parallel multithreaded due to immutable shared state (roundkey), but its prone for pattern attack.
// CBC, CFB, OFB is immune to pattern attack, but cannot be run in parallel with current implementation due to mutable shared state (IV),
// technically doable in parallel for decryption (Except OFB), see reference for operation modes
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Confidentiality_only_modes

// RCON value computed recursively via:  rcon = ( rcon << 1 ) ^ ( 0x11b & -( rcon >> 7 ) );
// https://en.wikipedia.org/wiki/AES_key_schedule#Rcon

// memory padding standards
// https://en.wikipedia.org/wiki/Padding_(cryptography)#Byte_padding

namespace aesni {

struct Encryptor256ECB
{
    __m128i m_key;
    __m128i m_roundkey[ 14 ];

    inline ~Encryptor256ECB() noexcept
    {
        // explicitly destory key values before its memory goes out of use
        m_key = _mm_xor_si128( m_key, m_key );
        for ( auto& it : m_roundkey ) it = _mm_xor_si128( it, it );
    }

    inline Encryptor256ECB( __m128i key ) noexcept
    : m_key{ key }
    {
        // for AES-128
        m_roundkey[ 0 ] = makeKeypart<0x01>( m_key );
        m_roundkey[ 1 ] = makeKeypart<0x02>( m_roundkey[ 0 ] );
        m_roundkey[ 2 ] = makeKeypart<0x04>( m_roundkey[ 1 ] );
        m_roundkey[ 3 ] = makeKeypart<0x08>( m_roundkey[ 2 ] );
        m_roundkey[ 4 ] = makeKeypart<0x10>( m_roundkey[ 3 ] );
        m_roundkey[ 5 ] = makeKeypart<0x20>( m_roundkey[ 4 ] );
        m_roundkey[ 6 ] = makeKeypart<0x40>( m_roundkey[ 5 ] );
        m_roundkey[ 7 ] = makeKeypart<0x80>( m_roundkey[ 6 ] );
        m_roundkey[ 8 ] = makeKeypart<0x1B>( m_roundkey[ 7 ] );
        m_roundkey[ 9 ] = makeKeypart<0x36>( m_roundkey[ 8 ] );
        m_roundkey[ 10 ] = makeKeypart<0x6C>( m_roundkey[ 9 ] );  // for AES-192
        m_roundkey[ 11 ] = makeKeypart<0xD8>( m_roundkey[ 10 ] ); // for AES-192
        m_roundkey[ 12 ] = makeKeypart<0xAB>( m_roundkey[ 11 ] ); // for AES-256
        m_roundkey[ 13 ] = makeKeypart<0x4D>( m_roundkey[ 12 ] ); // for AES-256
    }

    inline __m128i operator () ( __m128i block ) const noexcept
    {
        block = _mm_xor_si128( block, m_key );
        block = _mm_aesenc_si128( block, m_roundkey[ 0 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 1 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 2 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 3 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 4 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 5 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 6 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 7 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 8 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 9 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 10 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 11 ] );
        block = _mm_aesenc_si128( block, m_roundkey[ 12 ] );
        return _mm_aesenclast_si128( block, m_roundkey[ 13 ] );
    }

private:
    template <unsigned char RCON>
    static inline __m128i makeKeypart( __m128i key ) noexcept
    {
        __m128i keypart = _mm_aeskeygenassist_si128( key, RCON );
        keypart = _mm_shuffle_epi32( keypart, 0xFF );
        key = _mm_xor_si128( key, _mm_slli_si128( key, 4 ) );
        key = _mm_xor_si128( key, _mm_slli_si128( key, 4 ) );
        key = _mm_xor_si128( key, _mm_slli_si128( key, 4 ) );
        return _mm_xor_si128( key, keypart );
    };
};

struct Decryptor256ECB : public Encryptor256ECB
{
    inline Decryptor256ECB( __m128i key ) noexcept
    : Encryptor256ECB{ key }
    {
        m_roundkey[ 0 ] = _mm_aesimc_si128( m_roundkey[ 0 ] );
        m_roundkey[ 1 ] = _mm_aesimc_si128( m_roundkey[ 1 ] );
        m_roundkey[ 2 ] = _mm_aesimc_si128( m_roundkey[ 2 ] );
        m_roundkey[ 3 ] = _mm_aesimc_si128( m_roundkey[ 3 ] );
        m_roundkey[ 4 ] = _mm_aesimc_si128( m_roundkey[ 4 ] );
        m_roundkey[ 5 ] = _mm_aesimc_si128( m_roundkey[ 5 ] );
        m_roundkey[ 6 ] = _mm_aesimc_si128( m_roundkey[ 6 ] );
        m_roundkey[ 7 ] = _mm_aesimc_si128( m_roundkey[ 7 ] );
        m_roundkey[ 8 ] = _mm_aesimc_si128( m_roundkey[ 8 ] );
        m_roundkey[ 9 ] = _mm_aesimc_si128( m_roundkey[ 9 ] );
        m_roundkey[ 10 ] = _mm_aesimc_si128( m_roundkey[ 10 ] );
        m_roundkey[ 11 ] = _mm_aesimc_si128( m_roundkey[ 11 ] );
        m_roundkey[ 12 ] = _mm_aesimc_si128( m_roundkey[ 12 ] );
        // keep last roundkey [ 13 ] unchanged
    }

    inline __m128i operator () ( __m128i block ) const noexcept
    {
        block = _mm_xor_si128( block, m_roundkey[ 13 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 12 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 11 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 10 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 9 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 8 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 7 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 6 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 5 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 4 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 3 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 2 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 1 ] );
        block = _mm_aesdec_si128( block, m_roundkey[ 0 ] );
        return _mm_aesdeclast_si128( block, m_key );
    }
};

// added just for the usage convinience
namespace padding {

struct PKCS_5_7 {
    unsigned int m_size = 0;
    inline PKCS_5_7( unsigned int size ) noexcept : m_size{ size } {}
    inline unsigned char operator () () const noexcept { return static_cast<unsigned char>( m_size ); }
};

struct ISO_IEC_7816_4 {
    unsigned int m_once = 2;
    inline ISO_IEC_7816_4() noexcept = default;
    inline unsigned char operator () () noexcept { return ( m_once >>= 1 ) ? 0x80 : 0; }
};

struct ANSI_X9_23 {
    unsigned int m_size = 0;
    unsigned int m_count = 0;
    inline ANSI_X9_23( unsigned int size ) noexcept : m_size{ size } {}
    inline unsigned char operator () () noexcept { return ++m_count == m_size ? static_cast<unsigned char>( m_size ) : '\0'; }
};

} // namespace padding


namespace detail {
enum OP : int {
    CBC,
    CFB,
    OFB,
};

template <OP, typename TCipher>
struct Cipher : public TCipher
{
    using Super = TCipher;
     __m128i m_iv;

    inline Cipher( __m128i key, __m128i iv ) noexcept : TCipher{ key }, m_iv{ iv } {}
    inline ~Cipher() noexcept { m_iv = _mm_xor_si128( m_iv, m_iv ); }

    inline __m128i operator () ( __m128i block ) noexcept;
};
} // namespace detail


using Encryptor256CBC = detail::Cipher<detail::CBC, Encryptor256ECB>;
using Decryptor256CBC = detail::Cipher<detail::CBC, Decryptor256ECB>;
template<>
__m128i Encryptor256CBC::operator () ( __m128i block ) noexcept
{
    return m_iv = Super::operator()( _mm_xor_si128( block, m_iv ) );
}

template<>
__m128i Decryptor256CBC::operator () ( __m128i block ) noexcept
{
    __m128i iv = m_iv;
    m_iv = block;
    return _mm_xor_si128( Super::operator()( block ), iv );
}



using Encryptor256CFB = detail::Cipher<detail::CFB, Encryptor256ECB>;
template<>
__m128i Encryptor256CFB::operator () ( __m128i block ) noexcept
{
    return m_iv = _mm_xor_si128( block, Super::operator()( m_iv ) );
}

struct Decryptor256CFB : public Encryptor256ECB {
    using Super = Encryptor256ECB;
    __m128i m_iv;
    inline ~Decryptor256CFB() noexcept { m_iv = _mm_xor_si128( m_iv, m_iv ); };
    inline Decryptor256CFB( __m128i key, __m128i iv ) noexcept : Super{ key }, m_iv{ iv } {}

    __m128i operator () ( __m128i block ) noexcept
    {
        __m128i ret = _mm_xor_si128( block, Super::operator()( m_iv ) );
        m_iv = block;
        return ret;
    }
};

using Encryptor256OFB = detail::Cipher<detail::OFB, Encryptor256ECB>;
using Decryptor256OFB = Encryptor256OFB;
template<>
__m128i Encryptor256OFB::operator () ( __m128i block ) noexcept
{
    m_iv = Super::operator()( m_iv );
    return _mm_xor_si128( block, m_iv );
}

} // namespace aesni
