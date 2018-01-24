/** \ingroup Utility
 * @file
 * @author  devolve <http://sourceforge.net/projects/libb64>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * Public domain
 *
 * @brief Low-level Base64 encode functions
 * @section DESCRIPTION
 *
 * These functions provide the basice base64 encoding functionality. It's
 * preferable to use the higher-level functions in base64.h instead wherever
 * possible.
 *
 * This is part of the libb64 project, and has been placed in the public domain.
 * For details, see http://sourceforge.net/projects/libb64
 *
 * The cencode source provides support for base64 encoding data. It can be
 * used in conjunction with the cdecode source. It's used by base64, which
 * provides a higher-level interface to the functionality. 
 *
 */

/** \addtogroup Utility
 *  @{
 */

#ifndef BASE64_CENCODE_H
#define BASE64_CENCODE_H

// Defines

// Structure definitions

/**
 * @brief Internal enum used for base64 encoding
 */
typedef enum {
	step_A,
	step_B,
	step_C
} base64_encodestep;

/**
 * @brief Internal structure used for base64 encoding
 *
 * Opaque structure containing the private fields and context used for
 * base64 encoding. Use the functionality in base64.h in preference to these.
 */
typedef struct {
	base64_encodestep step;
	char result;
	int stepcount;
} base64_encodestate;

// Function prototypes

void base64_init_encodestate(base64_encodestate * state_in);
char base64_encode_value(char value_in);
int base64_encode_block(const char * plaintext_in, int length_in, char * code_out, base64_encodestate * state_in);
int base64_encode_blockend(char * code_out, base64_encodestate * state_in);

// Function definitions

#endif /* BASE64_CENCODE_H */

/** @} addtogroup Utility */

