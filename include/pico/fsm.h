/** \ingroup Protocol
 * @file
 * @author  Claudio Dettoni  <cd611@cl.cam.ac.uk>
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
 * @section DESCRIPTION
 *
 * This file contains definitions that are common to fsmpico.h and fsmservice.h
 */

/** \addtogroup Protocol
 *  @{
 */

#ifndef __FSM_H
#define __FSM_H (1)

typedef void (*FsmWrite)(char const * data, size_t length, void * user_data);
typedef void (*FsmSetTimeout)(int timeout, void * user_data);
typedef void (*FsmError)(void * user_data);
typedef void (*FsmReconnect)(void * user_data);
typedef void (*FsmListen)(void * user_data);
typedef void (*FsmDisconnect)(void * user_data);
typedef void (*FsmAuthenticated)(int status, void * user_data);
typedef void (*FsmSessionEnded)(void * user_data);
typedef void (*FsmStatusUpdate)(int state, void * user_data);

#endif

/** @} addtogroup Protocol */
