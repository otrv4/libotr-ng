/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OTRNG_WARN_H
#define OTRNG_WARN_H

typedef enum {
  OTRNG_WARN_NONE = 0,
  OTRNG_WARN_RECEIVED_UNENCRYPTED,
  // This warning happens when we receive a message that is not
  // valid, for example by not having a valid MAC.
  OTRNG_WARN_RECEIVED_NOT_VALID,
  // This warning will be emitted when we have tried to store
  // more old keys while ratcheting than we support.
  OTRNG_WARN_STORAGE_FULL,
  // This happens when we are asked to prepare a data message
  // for sending, but we are not in fact in encrypted state.
  OTRNG_WARN_SEND_NOT_ENCRYPTED,
  // This happens when we receive an invalid instance tag in a
  // prekey message
  OTRNG_WARN_MALFORMED,
} otrng_warning;


#endif /* OTRNG_WARN_H */
