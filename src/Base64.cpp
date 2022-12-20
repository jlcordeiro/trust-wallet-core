// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Base64.h"
#include <stdexcept>

namespace TW::Base64 {

using namespace TW;
using namespace std;

// The implementation below is heavily based on https://github.com/ReneNyffenegger/cpp-base64/

 // Base64 needs to sets of characters for encoding.
 // The first is for non-url content and the second
 // for URL.
static const char* base64_chars[2] = {
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789"
             "+/",

             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789"
             "-_"};

// Lookup table that maps back from each encoded character during decoding
static const unsigned char from_base64_chars[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 62, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

// simple wrapper around from_base64_chars that returns decoded bytes or,
// if not valid, throws the appropriate exception
static unsigned int pos_of_char(const unsigned char chr) {
    const auto lookup = from_base64_chars[chr];
    if (lookup != 64) return lookup;
    
    throw std::runtime_error("attempt to decode a value not in base64 char set");
}


// encode data into a base64 string. uses whatever set of characters is required
// depending on whetheror not it is looking at url content
static std::string encode_impl(const Data& val, bool url) {
    const size_t in_len = val.size();
    const size_t len_encoded = (in_len +2) / 3 * 4;
    const unsigned char trailing_char = '=';
    const char* base64_chars_ = base64_chars[url];

    std::string ret;
    ret.reserve(len_encoded);

    unsigned int pos = 0;
    while (pos < in_len) {
        ret.push_back(base64_chars_[(val[pos + 0] & 0xfc) >> 2]);

        if (pos+1 < in_len) {
           ret.push_back(base64_chars_[((val[pos + 0] & 0x03) << 4) + ((val[pos + 1] & 0xf0) >> 4)]);

           if (pos+2 < in_len) {
              ret.push_back(base64_chars_[((val[pos + 1] & 0x0f) << 2) + ((val[pos + 2] & 0xc0) >> 6)]);
              ret.push_back(base64_chars_[  val[pos + 2] & 0x3f]);
           }
           else {
              ret.push_back(base64_chars_[(val[pos + 1] & 0x0f) << 2]);
              ret.push_back(trailing_char);
           }
        }
        else {
            ret.push_back(base64_chars_[(val[pos + 0] & 0x03) << 4]);
            ret.push_back(trailing_char);
            ret.push_back(trailing_char);
        }

        pos += 3;
    }


    return ret;
}

// decode from a base64 encoded string into a Data object
// handles both url and non-url data seamlessly - albeit on a permissive manner
Data decode(const string& encoded_string) {
    if (encoded_string.empty()) {
        return Data();
    }

    const size_t length_of_string = encoded_string.size();
    if ((length_of_string % 4) != 0) {
        throw std::runtime_error("attempt to decode a value not in base64 char set");
    }

    size_t pos = 0;

  // The approximate length (bytes) of the decoded string might be one or
 // two bytes smaller, depending on the amount of trailing equal signs
 // in the encoded string. This approximation is needed to reserve
 // enough space in the string to be returned.
    const size_t approx_length_of_decoded_string = length_of_string / 4 * 3;
    Data ret;
    ret.reserve(approx_length_of_decoded_string);

    while (pos < length_of_string) {
    // Iterate over encoded input string in chunks of 4 bytes.
    //
    // The last chunk might be padded to make it 4 bytesas well, but this
    // is not required as per RFC 2045.
    //
    // All chunks except the last one produce three output bytes.
    // The last chunk produces at least one and up to three bytes.

       size_t pos_of_char_1 = pos_of_char(encoded_string.at(pos+1) );


    // Emit the first output byte
       ret.push_back(static_cast<std::string::value_type>( ( (pos_of_char(encoded_string.at(pos+0)) ) << 2 ) + ( (pos_of_char_1 & 0x30 ) >> 4)));

       if ( ( pos + 2 < length_of_string  )       &&  // Check for data that is not padded with equal signs (which is allowed by RFC 2045)
              encoded_string.at(pos+2) != '='     &&
              encoded_string.at(pos+2) != '.'         // accept URL-safe base 64 strings, too, so check for '.' also.
          )
       {

       // Emit second byte (which might not be produced in the last chunk).
          unsigned int pos_of_char_2 = pos_of_char(encoded_string.at(pos+2) );
          ret.push_back(static_cast<std::string::value_type>( (( pos_of_char_1 & 0x0f) << 4) + (( pos_of_char_2 & 0x3c) >> 2)));

          if ( ( pos + 3 < length_of_string )     &&
                 encoded_string.at(pos+3) != '='  &&
                 encoded_string.at(pos+3) != '.'
             )
          {

          // Emit third byte (which might not be produced in the last chunk).
             ret.push_back(static_cast<std::string::value_type>( ( (pos_of_char_2 & 0x03 ) << 6 ) + pos_of_char(encoded_string.at(pos+3))   ));
          }
       }

       pos += 4;
    }
    if (encoded_string[0] == '_') throw std::runtime_error("attempt to decode a value not in base64 char set");

    return ret;
}

Data decodeBase64Url(const string& val) {
    return decode(val);
}

std::string encode(const Data& val) {
    return encode_impl(val, false);
}

string encodeBase64Url(const Data& val) {
    return encode_impl(val, true);
}

} // namespace TW::Base64
