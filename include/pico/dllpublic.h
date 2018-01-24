/** \ingroup Utility
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * (C) Copyright Cambridge Authentication Ltd, 2017
 *
 * This file is part of libpico.
 *
 * Libpico is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Libpico is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with libpico. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *
 * @brief Provide Windows-specific functionality
 * @section DESCRIPTION
 *
 * Windows functions must be annotated to allow them to be exported for use
 * within a DLL. This header provides the required defines, as well as fixing
 * some minor differences between Windows and other environments.
 *
 */

/** \addtogroup Utility
 *  @{
 */

#ifndef __DLLPUBLIC_H
#define __DLLPUBLIC_H (1)

// Defines

// Structure definitions

#if defined(_WIN32) || defined(_WIN64)

#define DLL_PUBLIC __declspec(dllexport)
// Windows prefixed the function with _ for some questionable reasons
// In some versions of the compiler
#if defined(_MSC_VER) && (_MSC_VER < 1900) && !defined(snprintf)
#define snprintf _snprintf
#endif

#else
#define DLL_PUBLIC
#endif


// Function prototypes

// Function definitions

#endif

/** @} addtogroup Utility */

