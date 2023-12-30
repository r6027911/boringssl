
#ifndef JA3_SSL_CERT_COMPRESSION_H_
#define JA3_SSL_CERT_COMPRESSION_H_

#include <openssl/ssl.h>

namespace ja3::compression {
void enableBrotli(SSL_CTX *const ctx);
void enableZlib(SSL_CTX *const ctx);
void enableZstd(SSL_CTX *const ctx);

// Configures certificate compression callbacks on an SSL context.  The
// availability of individual algorithms may depend on the parameters with
// which the network stack is compiled.
void ConfigureCertificateCompression(SSL_CTX *ctx);


}  // namespace ja3
#endif  // NET_SSL_CERT_COMPRESSION_H_
