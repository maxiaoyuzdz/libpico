/** \ingroup Utility
 * @file
 * @author  devolve <http://sourceforge.net/projects/libb64>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * Public domain
 *
 * @brief Low-level Base64 decode functions
 * @section DESCRIPTION
 *
 * These functions provide the basice base64 decoding functionality. It's
 * preferable to use the higher-level functions in base64.h instead wherever
 * possible.
 *
 * This is part of the libb64 project, and has been placed in the public domain.
 * For details, see http://sourceforge.net/projects/libb64
 *
 * The code has been altered to remove newlines from the result.
 *
 * The cdecode source provides support for base64 decoding data. It can be
 * used in conjunction with the cencode source. It's used by base64, which
 * provides a higher-level interface to the functionality. 
 *
 */

/** \addtogroup Utility
 *  @{
 */

#ifndef BASE64_CDECODE_H
#define BASE64_CDECODE_H

// Defines

// Structure definitions

/**
 * @brief Internal enum used for base64 decoding
 */
typedef enum {
	step_a,
	step_b,
	step_c,
	step_d
} base64_decodestep;

/**
 * @brief Internal structure used for base64 decoding
 *
 * Opaque structure containing the private fields and context used for
 * base64 decoding. Use the functionality in base64.h in preference to these.
 */
typedef struct {
	base64_decodestep step;
	char plainchar;
} base64_decodestate;

// Function prototypes

void base64_init_decodestate(base64_decodestate* state_in);
int base64_decode_value(char value_in);
int base64_decode_block(const char * code_in, const int length_in, char * plaintext_out, base64_decodestate * state_in);

// Function definitions

#endif /* BASE64_CDECODE_H */

/** @} addtogroup Utility */

