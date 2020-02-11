#ifndef __zmix__crypto__bbs__included__
#define __zmix__crypto__bbs__included__

#ifdef __cplusplus
extern "C" {
#endif

extern int32_t zmix_bbs_sign(const struct ByteBuffer* const messages,
                             const struct ByteBuffer* const sign_key,
                             const struct ByteBuffer* const ver_key,
                             const struct ByteBuffer* signature,
                             const struct ExternError* err);

extern int32_t zmix_bbs_verify(const struct ByteBuffer* const messages,
                               const struct ByteBuffer* const ver_key,
                               const struct ByteBuffer* const signature,
                               const struct ExternError* err);
#ifdef __cplusplus
}
#endif

#endif
