

#include <openssl/base.h>
#include "../../internal.h"
#include <brotli/decode.h>
#include <brotli/encode.h>
#include "cert_compression.h"
#include <zlib.h>
#include <zstd.h>


namespace ja3::compression {

    int DecompressBrotliCert(SSL *ssl, CRYPTO_BUFFER **out, size_t uncompressed_len,
                         const uint8_t *in, size_t in_len) {
        uint8_t *data;
        bssl::UniquePtr<CRYPTO_BUFFER> decompressed(
        CRYPTO_BUFFER_alloc(&data, uncompressed_len));
        if (!decompressed) {
            return 0;
        }

        size_t output_size = uncompressed_len;
        if (BrotliDecoderDecompress(in_len, in, &output_size, data) !=
            BROTLI_DECODER_RESULT_SUCCESS ||
            output_size != uncompressed_len) {
            return 0;
        }

        *out = decompressed.release();
        return 1;
    }
    
    void ja3::compression::enableBrotli(SSL_CTX *const ctx) {
        SSL_CTX_add_cert_compression_alg(ctx, TLSEXT_cert_compression_brotli,
                                   nullptr /* compression not supported */,
                                   DecompressBrotliCert);
    }


    int DecompressZlibCert(SSL *ssl, CRYPTO_BUFFER **out,
                             size_t uncompressed_len, const uint8_t *in,
                             size_t in_len) {
        uint8_t *data;
        bssl::UniquePtr<CRYPTO_BUFFER> decompressed(CRYPTO_BUFFER_alloc(&data, uncompressed_len));
        if (!decompressed) {
            return 0;
        }

        uLongf destLen = (uLongf)uncompressed_len;
        if (uncompress(data, &destLen, in, in_len) != Z_OK) {
            return 0;
        }
        return 1;
    }

    void ja3::compression::enableZlib(SSL_CTX *const ctx) {
        SSL_CTX_add_cert_compression_alg(
            ctx, TLSEXT_cert_compression_zlib,
            nullptr /* compression not supported */, 
            DecompressZlibCert);
    }


    int DecompressZstdCert(SSL *ssl, CRYPTO_BUFFER **out,
                             size_t uncompressed_len, const uint8_t *in,
                             size_t in_len) {
        uint8_t *data;
        bssl::UniquePtr<CRYPTO_BUFFER> decompressed(CRYPTO_BUFFER_alloc(&data, uncompressed_len));
        if (!decompressed) {
            return 0;
        }

        size_t const dSize = ZSTD_decompress(data, uncompressed_len, in, in_len);
        if (ZSTD_isError(dSize)) {
            return 0;
        }

        return 1;
    }

    void ja3::compression::enableZstd(SSL_CTX *const ctx) {
        SSL_CTX_add_cert_compression_alg(
            ctx, TLSEXT_cert_compression_zstd,
            nullptr /* compression not supported */, 
            DecompressZstdCert);
    }

}  
